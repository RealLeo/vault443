#!/usr/bin/python3
"""Extract distro Qt/CMake development packages locally; never installs packages."""
import apt
import concurrent.futures
import hashlib
from pathlib import Path
import subprocess
import urllib.request

root = Path(__file__).resolve().parents[1]
archives = root / '.cache/debs'
prefix = root / '.cache/qt'
archives.mkdir(parents=True, exist_ok=True)
prefix.mkdir(parents=True, exist_ok=True)
cache = apt.Cache()
requested = ['qt6-base-dev', 'qt6-declarative-dev', 'qt6-base-dev-tools',
 'qt6-declarative-dev-tools', 'qt6-l10n-tools', 'qt6-wayland', 'qt6-qpa-plugins',
 'qml6-module-qtquick', 'qml6-module-qtquick-controls',
 'qml6-module-qtquick-layouts', 'qml6-module-qtquick-window',
 'qml6-module-qtqml-workerscript', 'qml6-module-qtquick-templates',
 'qml6-module-qtquick-dialogs', 'qml6-module-qtqml',
 'cmake', 'ninja-build', 'xvfb']
for name in requested:
    cache[name].mark_install(auto_fix=True, auto_inst=True, from_user=True)
packages = {p.name: p.candidate for p in cache.get_changes()}
for p in cache:
    if p.is_installed and (p.name.startswith('libqt6') or p.name in requested):
        packages[p.name] = p.candidate
for name in requested:
    packages[name] = cache[name].candidate

def fetch(item):
    name, version = item
    target = archives / Path(version.filename).name
    expected = version.record.get('SHA256')
    if not target.exists() or (expected and hashlib.sha256(target.read_bytes()).hexdigest() != expected):
        uri = version.uri.replace('http://', 'https://')
        with urllib.request.urlopen(uri, timeout=60) as response:
            content = response.read()
        if expected and hashlib.sha256(content).hexdigest() != expected:
            raise RuntimeError('Checksum mismatch: ' + name)
        target.write_bytes(content)
    return target

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    files = list(pool.map(fetch, packages.items()))
for path in files:
    subprocess.run(['dpkg-deb', '-x', str(path), str(prefix)], check=True)
print(f'Extracted {len(files)} packages into {prefix}; no system packages modified.')
