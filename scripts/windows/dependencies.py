#!/usr/bin/env python3
"""Resolve, download and seal official Windows build/runtime dependencies.

`resolve` is an explicit lock refresh. Normal `fetch` uses only the checked-in
URLs; `seal` records SHA-256 after the first trusted HTTPS download. Completed
downloads are verified against that lock on every subsequent run.
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET

from vm import fetch

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'packaging/windows/dependencies-lock.json'
QT_BASE = 'https://download.qt.io/online/qtsdkrepository/windows_x86/desktop/qt6_6120/qt6_6120_msvc2022_64/'


def metadata(name, url, sha256=''):
    request = urllib.request.Request(url, method='HEAD')
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            size = int(response.headers['Content-Length'])
            final_url = response.geturl()
    except Exception as error:
        raise RuntimeError(f'{name}: {error} ({url})') from error
    # GitHub release redirects contain expiring SAS tokens. Keep their stable
    # official URL; the SHA-256 lock pins the actual bytes independently.
    source = final_url if final_url.startswith('https://download.visualstudio.microsoft.com/') else url
    return dict(name=name, url=source, bytes=size, sha256=sha256)


def resolve():
    with urllib.request.urlopen(QT_BASE + 'Updates.xml', timeout=30) as response:
        document = ET.fromstring(response.read(16 << 20))
    selected = []
    for package in document.findall('PackageUpdate'):
        name = package.findtext('Name')
        if name not in ['qt.qt6.6120.win64_msvc2022_64', 'qt.qt6.6120.addons.qtshadertools.win64_msvc2022_64']:
            continue
        version = package.findtext('Version')
        for archive in package.findtext('DownloadableArchives').split(', '):
            if archive.startswith(('qtbase-', 'qtdeclarative-', 'qttools-', 'qttranslations-', 'qtshadertools-')):
                selected.append((archive, QT_BASE + name + '/' + version + archive, ''))
    selected += [
        ('python-3.12.10-embed-amd64.zip', 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip', ''),
        ('xray-windows-x64.zip', 'https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-windows-64.zip', 'b17a619343c11b89d8faf36278298856749b15c52277d875d32051b33dcda617'),
        ('wintun-0.14.1.zip', 'https://www.wintun.net/builds/wintun-0.14.1.zip', '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'),
        ('vs-BuildTools-2022.exe', 'https://download.visualstudio.microsoft.com/download/pr/6bd63d7f-1818-4e03-a552-9feb11496c19/5dc747350fb0589f908915c7b5fa52ec22d22b37ae2e5f4964d83519667498b2/vs_BuildTools.exe', '5dc747350fb0589f908915c7b5fa52ec22d22b37ae2e5f4964d83519667498b2'),
        ('innosetup-7.1.1.exe', 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe', ''),
        ('qtbase-everywhere-src-6.12.0.tar.xz', 'https://download.qt.io/official_releases/qt/6.12/6.12.0/submodules/qtbase-everywhere-src-6.12.0.tar.xz', ''),
        ('qtbase-CVE-2026-105924.diff', 'https://download.qt.io/official_releases/qt/6.12/CVE-2026-105924-qtbase-6.12.diff', ''),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        assets = list(executor.map(lambda item: metadata(*item), selected))
    return dict(msvcVersion='17.14.44', qtVersion='6.12.0', xrayVersion='26.9.30', innoVersion='7.1.1', assets=assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['resolve', 'fetch', 'seal'])
    parser.add_argument('--root', type=Path, default=Path('/var/www/projects/windows/sdk'))
    parser.add_argument('--chunk-mib', type=int, default=128)
    args = parser.parse_args()
    if args.action == 'resolve':
        if LOCK.exists():
            raise SystemExit('Lock already exists; remove it explicitly before refreshing dependencies')
        lock = resolve()
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        LOCK.write_text(json.dumps(lock, indent=2) + '\n')
        print(f'Resolved {len(lock["assets"])} official dependencies')
        return
    lock = json.loads(LOCK.read_text())
    if args.action == 'fetch':
        def download(asset):
            item = (asset['name'], (asset['name'], asset['url'], asset['bytes']))
            fetch(item, args.root, args.chunk_mib << 20)
            path = args.root / 'media' / asset['name']
            if path.exists() and asset['sha256']:
                with path.open('rb') as source:
                    actual = hashlib.file_digest(source, 'sha256').hexdigest()
                if actual != asset['sha256']:
                    raise RuntimeError(f'Checksum mismatch: {asset["name"]}')
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            list(executor.map(download, lock['assets']))
        return
    for asset in lock['assets']:
        path = args.root / 'media' / asset['name']
        if not path.exists() or path.stat().st_size != asset['bytes']:
            raise SystemExit(f'Incomplete dependency: {asset["name"]}')
        with path.open('rb') as source:
            actual = hashlib.file_digest(source, 'sha256').hexdigest()
        if asset['sha256'] and actual != asset['sha256']:
            raise SystemExit(f'Checksum mismatch: {asset["name"]}')
        asset['sha256'] = actual
    LOCK.write_text(json.dumps(lock, indent=2) + '\n')
    print('Dependency lock sealed with SHA-256 for every archive')


if __name__ == '__main__':
    main()
