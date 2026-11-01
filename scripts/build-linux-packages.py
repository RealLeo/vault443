#!/usr/bin/env python3
"""Build native x86-64 distro packages in Docker; never install on the host.

Prerequisites: the existing locked Go/helpers/Xray caches, a current vulnerability
report, and Docker. Runtime/build image package inventories accompany each file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / 'VERSION').read_text().strip()
TARGETS = ('debian13', 'fedora44', 'arch')


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, cwd=ROOT, **kwargs)


def container(target, out, script, *, user=True):
    args = ['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--mount', f'type=bind,src={ROOT},dst=/src,readonly',
            '--mount', f'type=bind,src={out},dst=/out', '-e', 'HOME=/tmp',
            '-e', 'QT_QPA_PLATFORM=offscreen', '-e', 'QT_QUICK_BACKEND=software']
    if user:
        args += ['--user', f'{os.getuid()}:{os.getgid()}']
    return run(*args, f'vault443-linux-build:{target}', '/bin/bash', '-euc', script)


def build(target, args):
    out = ROOT / '.cache/distro' / target
    out.mkdir(parents=True, exist_ok=True)
    image = f'vault443-linux-build:{target}'
    if not args.skip_image:
        run('docker', 'build', '-f', f'packaging/linux/Dockerfile.{target}', '-t', image, 'packaging/linux')
    # Choose only the native Linguist executable, never the Ubuntu cache in /src.
    linguist = '/usr/lib64/qt6/bin/lrelease' if target == 'fedora44' else '/usr/lib/qt6/bin/lrelease'
    if not args.repack:
        container(target, out, f'''
        cmake -S /src -B /out/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_SKIP_RPATH=ON -DVAULT443_LRELEASE={linguist}
        cmake --build /out/build --parallel {args.jobs}
        ctest --test-dir /out/build --output-on-failure
    ''')
    container(target, out, 'pkg-config --modversion Qt6Core > /out/qt-version')
    run('python3', 'scripts/build-service.py', 'amd64', out / 'build')
    stage = out / 'payload'
    env = dict(os.environ, BUILD_DIR=str(out / 'build'), PACKAGE_STAGE=str(stage))
    run('bash', 'scripts/stage-package.sh', 'amd64', env=env)
    dest = ROOT / 'dist/linux' / target
    dest.mkdir(parents=True, exist_ok=True)
    if target == 'debian13':
        package = dest / f'vault443_{VERSION}-1debian13_amd64.deb'
        # Native Debian 13 build: explicitly require its ABI, not Ubuntu's.
        env.update(PACKAGE_VERSION=f'{VERSION}-1debian13', PACKAGE_OUTPUT=str(package), LIBC_MIN='2.41', QT_MIN='6.8')
        run('bash', 'scripts/package.sh', 'amd64', env=env)
    else:
        # /usr/sbin is a symlink in merged-bin distributions. Pacman must not
        # receive a real directory there. Fixed runtime /usr/sbin paths resolve
        # to these binaries through the distro-owned symlink.
        for file in (stage / 'usr/sbin').iterdir():
            shutil.move(file, stage / 'usr/bin' / file.name)
        (stage / 'usr/sbin').rmdir()
        for path in [stage / 'usr/lib/systemd/system/vault443.service',
                     stage / 'usr/lib/systemd/system/vault443-guard.service',
                     stage / 'usr/share/dbus-1/system-services/org.vault443.Service1.service']:
            path.write_text(path.read_text().replace('/usr/sbin/vault443d', '/usr/bin/vault443d'))
        lifecycle = stage / 'usr/lib/vault443/package-lifecycle'
        shutil.copyfile(ROOT / 'packaging/linux/package-lifecycle', lifecycle)
        lifecycle.chmod(0o755)
        if target == 'fedora44':
            # List regular files, plus application-owned directories only.
            files = ['/' + str(p.relative_to(stage)) for p in sorted(stage.rglob('*')) if p.is_file()]
            owned = ['usr/lib/vault443', 'usr/share/doc/vault443']
            dirs = [p for base in owned for p in [stage / base, *(stage / base).rglob('*')] if p.is_dir()]
            (out / 'rpm-files').write_text('\n'.join(['%dir /' + str(p.relative_to(stage)) for p in dirs] + files) + '\n')
            container(target, out, f'''rpmbuild -bb /src/packaging/linux/vault443.spec \
                --define '_topdir /out/rpm' --define 'product_version {VERSION}' \
                --define 'payload /out/payload' --define 'payload_files /out/rpm-files'
            ''')
            built = list((out / 'rpm/RPMS/x86_64').glob(f'vault443-{VERSION}-*.rpm'))
            if len(built) != 1:
                raise SystemExit('Expected exactly one Fedora RPM')
            package = dest / built[0].name
            shutil.copyfile(built[0], package)
        else:
            with tarfile.open(out / 'payload.tar', 'w') as tar:
                tar.add(stage, arcname='payload')
            digest = hashlib.sha256((out / 'payload.tar').read_bytes()).hexdigest()
            qt_min = '.'.join((out / 'qt-version').read_text().strip().split('.')[:2])
            recipe = (ROOT / 'packaging/linux/PKGBUILD').read_text().replace('@VERSION@', VERSION).replace('@SHA256@', digest).replace('@QT_MIN@', qt_min)
            (out / 'PKGBUILD').write_text(recipe)
            shutil.copyfile(ROOT / 'packaging/linux/vault443.install', out / 'vault443.install')
            container(target, out, 'cd /out; PACKAGER="Vault 443 project" makepkg --force --cleanbuild --noconfirm')
            package = dest / f'vault443-{VERSION}-1-x86_64.pkg.tar.zst'
            shutil.copyfile(out / package.name, package)
    # Keep provenance next to the package; runtime sources contain no test data.
    inventory = {'debian13': "dpkg-query -W -f='${Package} ${Version}\\n'",
                 'fedora44': "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n'",
                 'arch': 'pacman -Q'}[target]
    container(target, out, f'{inventory} | sort > /out/packages.txt; cat /etc/os-release > /out/os-release')
    image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip()
    manifest = dict(productVersion=VERSION, target=target, architecture='x86_64', image=image_id,
                    package=package.name, sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                    osRelease=(out / 'os-release').read_text(), packages=(out / 'packages.txt').read_text().splitlines())
    (dest / (package.name + '.build.json')).write_text(json.dumps(manifest, indent=2) + '\n')
    (dest / (package.name + '.sha256')).write_text(manifest['sha256'] + '  ' + package.name + '\n')
    print('Built', package, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('targets', choices=TARGETS, nargs='+')
    parser.add_argument('--skip-image', action='store_true', help='Reuse previously built native Docker images')
    parser.add_argument('--repack', action='store_true', help='Reuse the tested GUI for packaging/documentation-only changes')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if os.getuid() == 0:
        raise SystemExit('Run as your regular user with Docker access; makepkg refuses root')
    if not 1 <= args.jobs <= 64:
        raise SystemExit('jobs must be in 1..64')
    run('python3', 'scripts/check-vulnerabilities.py', '--verify')
    for target in args.targets:
        build(target, args)
