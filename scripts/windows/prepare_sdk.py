#!/usr/bin/env python3
"""Verify locked SDK files, unpack Qt, apply the published QtBase fix, bundle for Guest Control."""
import argparse, hashlib, json, subprocess, tarfile, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--sdk', type=Path, default=Path('/var/www/projects/windows/sdk'))
a = p.parse_args()
lock = json.loads((ROOT / 'packaging/windows/dependencies-lock.json').read_text())
for asset in lock['assets']:
    path = a.sdk / 'media' / asset['name']
    with path.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != asset['sha256']:
            raise SystemExit('SDK checksum mismatch: ' + asset['name'])
qt = a.sdk / 'qt'
qt.mkdir(exist_ok=True)
for asset in lock['assets']:
    if asset['name'].startswith('qt') and asset['name'].endswith('.7z'):
        subprocess.run(['7z', 'x', '-y', '-bd', '-bso0', '-o' + str(qt), str(a.sdk / 'media' / asset['name'])], check=True)
source = a.sdk / 'qtbase-everywhere-src-6.12.0'
if not source.exists():
    with tarfile.open(a.sdk / 'media/qtbase-everywhere-src-6.12.0.tar.xz') as archive:
        archive.extractall(a.sdk, filter='data')
patch = a.sdk / 'media/qtbase-CVE-2026-105924.diff'
marker = source / '.vault443-patched'
if not marker.exists():
    subprocess.run(['patch', '-p1', '-i', str(patch)], cwd=source, check=True)
    marker.write_text(hashlib.sha256(patch.read_bytes()).hexdigest() + '\n')
for directory, name in [(qt, 'qt-sdk.zip'), (source, 'qtbase-source.zip')]:
    with zipfile.ZipFile(a.sdk / name, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
        for file in sorted(directory.rglob('*')):
            if file.is_file(): archive.write(file, file.relative_to(directory))
    print(name, (a.sdk / name).stat().st_size, flush=True)
