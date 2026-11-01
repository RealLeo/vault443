#!/usr/bin/env python3
"""Build the pinned, separate AWG core without changing the system Go toolchain.

Fetches are bounded and checksum-verified. Compilation uses only the downloaded
module cache. --offline forbids all downloading; --fetch-only prepares a cache.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'packaging/amneziawg-lock.json').read_text())
CACHE = ROOT / '.cache/amneziawg'


def fetch(url, destination, digest, offline):
    if not destination.exists():
        if offline:
            raise SystemExit(f'Offline build needs cached archive: {destination}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix('.download')
        try:
            with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as output:
                remaining = 256 << 20
                while chunk := response.read(min(1 << 20, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise SystemExit('Pinned archive exceeds the 256 MiB download limit')
                    output.write(chunk)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    with destination.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != digest:
        raise SystemExit(f'Checksum mismatch: {destination}')


def extract(archive, directory):
    directory.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        source.extractall(directory, filter='data')


def modules(go, environment, source):
    raw = subprocess.check_output([str(go), 'list', '-mod=readonly', '-deps', '-json', '.'], cwd=source, env=environment).decode()
    decoder = json.JSONDecoder()
    seen = set()
    while raw.strip():
        item, offset = decoder.raw_decode(raw.lstrip())
        module = item.get('Module')
        if module and module['Path'] not in seen:
            seen.add(module['Path'])
            yield module
        raw = raw.lstrip()[offset:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=['amd64', 'arm64'])
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--fetch-only', action='store_true')
    args = parser.parse_args()
    host = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or not host:
        raise SystemExit('Build the Linux core on an amd64 or arm64 Linux host')
    archive = CACHE / 'source.tar.gz'
    fetch(LOCK['sourceUrl'], archive, LOCK['sourceSha256'], args.offline)
    source = CACHE / ('amneziawg-go-' + LOCK['commit'])
    if not source.exists():
        extract(archive, CACHE)
    toolchain = CACHE / ('go-' + LOCK['goVersion'] + '-' + host)
    goarchive = CACHE / ('go' + LOCK['goVersion'] + '.linux-' + host + '.tar.gz')
    fetch('https://go.dev/dl/' + goarchive.name, goarchive, LOCK['goArchives'][host], args.offline)
    go = toolchain / 'go/bin/go'
    if not go.exists():
        extract(goarchive, toolchain)
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='',
                       GOROOT=str(toolchain / 'go'),
                       GOMODCACHE=str(CACHE / 'modules'), GOCACHE=str(CACHE / 'build-cache'),
                       CGO_ENABLED='0', GOOS='linux', GOARCH=args.architecture)
    if not args.offline:
        subprocess.run([str(go), 'mod', 'download'], cwd=source, env=environment, check=True)
    if args.fetch_only:
        return
    environment.update(GOPROXY='off', GOSUMDB='off')
    output = CACHE / args.architecture
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(go), 'build', '-mod=readonly', '-buildvcs=false', '-trimpath',
                    '-ldflags=-s -w -X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory='
                    + LOCK['socketDirectory'], '-o', str(output / 'amneziawg-go'), '.'],
                   cwd=source, env=environment, check=True)
    licenses = output / 'licenses'
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(toolchain / 'go/LICENSE', licenses / 'Go-LICENSE')
    manifest = []
    for module in modules(go, environment, source):
        directory = Path(module.get('Dir', source if module.get('Main') else '/nonexistent'))
        names = []
        for license_file in directory.iterdir() if directory.is_dir() else []:
            if license_file.is_file() and license_file.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                name = module['Path'].replace('/', '_') + '--' + license_file.name
                shutil.copyfile(license_file, licenses / name)
                names.append(name)
        manifest.append({'module': module['Path'], 'version': module.get('Version', LOCK['tag']), 'licenses': names})
    (licenses / 'modules.json').write_text(json.dumps(manifest, indent=2) + '\n')
    binary = output / 'amneziawg-go'
    checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
    (output / 'build.json').write_text(json.dumps(dict(LOCK, architecture=args.architecture,
                                                     binarySha256=checksum), indent=2) + '\n')
    print(f'AmneziaWG {LOCK["version"]} {args.architecture}: {checksum}')


if __name__ == '__main__':
    main()
