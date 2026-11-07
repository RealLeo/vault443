#!/usr/bin/env python3
"""Cross-build the locked Go engines and stage a reviewable Windows source bundle."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
wf_spec = importlib.util.spec_from_file_location('wf_patch', ROOT / 'scripts/windows/wf_patch.py')
wf_patch = importlib.util.module_from_spec(wf_spec)
wf_spec.loader.exec_module(wf_patch)
spec = importlib.util.spec_from_file_location('toolchain', ROOT / 'scripts/toolchain.py')
toolchain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toolchain)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def backend():
    reviewed_wf = wf_patch.verify(ROOT)
    go, env = toolchain.ensure(offline=True)
    env.update(GOOS='windows', GOARCH='amd64', CGO_ENABLED='0', GOPROXY='off')
    output = ROOT / 'build-windows'
    output.mkdir(exist_ok=True)
    version = (ROOT / 'VERSION').read_text().strip()
    targets = [('vault443d.exe', ROOT, './cmd/vault443d'),
               ('vault443-cli.exe', ROOT, './cmd/vault443-cli'),
               ('vault443-access.exe', ROOT, './cmd/vault443-access'),
               ('vault443-tunnel.exe', ROOT / 'helpers/windows-tunnel', '.'),
               ('vault443-outline.exe', ROOT / 'helpers/outline', '.')]
    for name, cwd, package in targets:
        build_env = dict(env)
        if name == 'vault443-outline.exe':
            build_env['GOMODCACHE'] = str(ROOT / '.cache/outline/modules')
        flags = f'-s -w -X main.version={version}' if name == 'vault443-outline.exe' else '-s -w'
        subprocess.run([str(go), 'build', '-mod=readonly', '-buildvcs=false', '-trimpath', '-ldflags=' + flags,
                        '-o', str(output / name), package], cwd=cwd, env=build_env, check=True)
        toolchain.verify_binary(go, build_env, output / name)
        print(name, digest(output / name), flush=True)
    manifest = dict(productVersion=version, goVersion=toolchain.LOCK['version'], os='windows', architecture='amd64',
                    revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    modified=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                    binaries={name: digest(output / name) for name, _, _ in targets},
                    dependencyPatches={wf_patch.MODULE: reviewed_wf})
    (output / 'backend-build.json').write_text(json.dumps(manifest, indent=2) + '\n')


def stage(destination, sdk):
    destination.mkdir(parents=True, exist_ok=True)
    app = destination / 'app'
    app.mkdir(exist_ok=True)
    for name in ('vault443d.exe', 'vault443-cli.exe', 'vault443-access.exe',
                 'vault443-tunnel.exe', 'vault443-outline.exe'):
        shutil.copy2(ROOT / 'build-windows' / name, app / name)
    with zipfile.ZipFile(sdk / 'media/xray-windows-x64.zip') as archive:
        (app / 'xray.exe').write_bytes(archive.read('xray.exe'))
        for name in archive.namelist():
            if Path(name).name.upper().startswith(('LICENSE', 'NOTICE')):
                (app / ('Xray-' + Path(name).name)).write_bytes(archive.read(name))
    with zipfile.ZipFile(sdk / 'media/wintun-0.14.1.zip') as archive:
        (app / 'wintun.dll').write_bytes(archive.read('wintun/bin/amd64/wintun.dll'))
        (app / 'Wintun-LICENSE.txt').write_bytes(archive.read('wintun/LICENSE.txt'))
    runtime = sdk / 'openvpn'
    if not (runtime / 'openvpn.exe').is_file():
        raise ValueError('Extract the pinned OpenVPN runtime with openvpn_runtime.py before staging')
    shutil.copytree(runtime, app / 'openvpn', dirs_exist_ok=True)
    shutil.copy2(ROOT / 'LICENSE', app / 'Vault443-LICENSE.txt')
    shutil.copy2(ROOT / 'scripts/windows/provision.ps1', destination / 'provision.ps1')
    shutil.copy2(ROOT / 'scripts/windows/extract_sources.py', destination / 'extract_sources.py')
    if (ROOT / 'build-windows/backend-build.json').exists():
        shutil.copy2(ROOT / 'build-windows/backend-build.json', app / 'backend-build.json')
    # Include the current working sources, including new files, not just HEAD.
    files = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH') or subprocess.check_output(['git','show','-s','--format=%ct','HEAD'],cwd=ROOT,text=True).strip())
    timestamp = time.gmtime(max(epoch,315532800))[:6]
    with zipfile.ZipFile(destination / 'source.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(set(files)):
            path = ROOT / name
            if not name or not path.is_file() or name.startswith(('website/', 'design/', '.agents/')):
                continue
            entry=zipfile.ZipInfo(name,timestamp)
            entry.compress_type=zipfile.ZIP_DEFLATED
            entry.create_system=3
            entry.external_attr=(path.stat().st_mode&0xffff)<<16
            archive.writestr(entry,path.read_bytes())
    print(f'Staged Windows runtime and working source in {destination}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['backend', 'stage'])
    parser.add_argument('--destination', type=Path, default=Path('/var/www/projects/windows/exchange'))
    parser.add_argument('--sdk', type=Path, default=Path('/var/www/projects/windows/sdk'))
    args = parser.parse_args()
    if args.action == 'backend':
        backend()
    else:
        stage(args.destination, args.sdk)


if __name__ == '__main__':
    main()
