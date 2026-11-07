#!/usr/bin/env python3
"""Verify and extract the pinned official OpenVPN/Wintun-compatible runtime.

The upstream MSI is a source container only: it is never installed on the host.
7-Zip extracts the embedded CAB; we copy only required engine DLLs and licenses.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'packaging/windows/openvpn-lock.json'
FILES = {
    'bin.openvpn.exe': 'openvpn.exe',
    'libcrypto_3_x64.dll': 'libcrypto-3-x64.dll',
    'libssl_3_x64.dll': 'libssl-3-x64.dll',
    'libpkcs11_helper_1.dll': 'libpkcs11-helper-1.dll',
    'legacy.dll': 'legacy.dll',
    'vcruntime140.dll': 'vcruntime140.dll',
    'license.txt': 'OpenVPN-LICENSE.txt',
    'LICENSE_OpenSSL.txt': 'OpenSSL-LICENSE.txt',
}


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'stage'])
    parser.add_argument('--sdk', type=Path, default=Path('/var/www/projects/windows/sdk'))
    parser.add_argument('--destination', type=Path, help='stage engine directory, default SDK/openvpn')
    args = parser.parse_args()
    lock = json.loads(LOCK.read_text())
    media = args.sdk / 'media'
    media.mkdir(parents=True, exist_ok=True)
    for asset in lock['assets']:
        path = media / asset['name']
        if not path.exists():
            if args.action != 'fetch':
                raise SystemExit('Missing pinned source/runtime: ' + asset['name'])
            temporary = path.with_suffix(path.suffix + '.partial')
            with urllib.request.urlopen(asset['url'], timeout=60) as source, temporary.open('wb') as output:
                shutil.copyfileobj(source, output, length=1 << 20)
            if temporary.stat().st_size != asset['bytes'] or sha(temporary) != asset['sha256']:
                temporary.unlink(missing_ok=True)
                raise SystemExit('Download checksum mismatch: ' + asset['name'])
            temporary.replace(path)
        if path.stat().st_size != asset['bytes'] or sha(path) != asset['sha256']:
            raise SystemExit('Pinned checksum mismatch: ' + asset['name'])
    if args.action == 'fetch':
        print(f'Verified {len(lock["assets"])} OpenVPN assets')
        return
    destination = args.destination or args.sdk / 'openvpn'
    destination.mkdir(parents=True, exist_ok=True)
    msi = media / next(asset['name'] for asset in lock['assets'] if asset['name'].endswith('.msi'))
    for source, name in FILES.items():
        content = subprocess.check_output(['7z', 'x', '-so', str(msi), source])
        if not content or len(content) > 16 << 20:
            raise SystemExit('Unexpected MSI member: ' + source)
        (destination / name).write_bytes(content)
    wintun_archive = media / 'wintun-0.14.1.zip'
    if sha(wintun_archive) != '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51':
        raise SystemExit('Pinned signed Wintun archive mismatch')
    with zipfile.ZipFile(wintun_archive) as archive:
        (destination / 'wintun.dll').write_bytes(archive.read('wintun/bin/amd64/wintun.dll'))
        (destination / 'Wintun-LICENSE.txt').write_bytes(archive.read('wintun/LICENSE.txt'))
    source_dir = destination / 'sources'
    source_dir.mkdir(exist_ok=True)
    for asset in lock['assets']:
        if not asset['name'].endswith('.msi'):
            shutil.copy2(media / asset['name'], source_dir / asset['name'])
    with tarfile.open(media / 'pkcs11-helper-1.31.0.tar.bz2') as archive:
        for name in ['COPYING', 'COPYING.BSD', 'COPYING.GPL']:
            (destination / ('PKCS11-helper-' + name + '.txt')).write_bytes(archive.extractfile('pkcs11-helper-1.31.0/' + name).read())
    with tarfile.open(media / 'lzo-2.10.tar.gz') as archive:
        (destination / 'LZO-COPYING.txt').write_bytes(archive.extractfile('lzo-2.10/COPYING').read())
    shutil.copy2(LOCK, destination / 'dependency-lock.json')
    (destination / 'SOURCE-NOTICE.txt').write_text(
        'OpenVPN is GPL-2.0 with the upstream OpenSSL/Apache linking exceptions.\n'
        'The exact upstream OpenVPN source commit, release source, and component sources are included in sources/.\n'
        'The OpenVPN binary and DLLs are unmodified members of the official locked MSI.\n'
        'Only the signed Wintun supplied in the Vault443 installation is used; bundled DCO/TAP/service executables are excluded.\n'
        'Source URLs, versions and SHA-256 are recorded in dependency-lock.json.\n', encoding='utf-8')
    manifest = dict(version=lock['version'], package=lock['windowsPackageVersion'],
                    sourceCommit=lock.get('sourceCommit'), files={})
    for path in sorted(destination.rglob('*')):
        if path.is_file() and path.name != 'runtime-build.json':
            manifest['files'][str(path.relative_to(destination))] = sha(path)
    (destination / 'runtime-build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Staged pinned OpenVPN {lock["version"]} runtime in {destination}')


if __name__ == '__main__':
    main()
