"""One verified, private Go toolchain for production binaries and tests."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'packaging/go-toolchain-lock.json').read_text())
CACHE = ROOT / '.cache/toolchains'

def fetch(url, destination, digest, offline):
    if not destination.exists():
        if offline:
            raise SystemExit(f'Missing pinned archive: {destination}; run python3 scripts/go.py --fetch-only')
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix('.download')
        try:
            with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as output:
                remaining = 256 << 20
                while chunk := response.read(min(1 << 20, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise SystemExit('Pinned archive exceeds 256 MiB')
                    output.write(chunk)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    with destination.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise SystemExit(f'Checksum mismatch: {destination}')

def extract(archive, directory):
    directory.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        source.extractall(directory, filter='data')

def ensure(offline=True):
    host = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or not host:
        raise SystemExit('Go builds require Linux amd64 or arm64')
    archive = CACHE / f'go{LOCK["version"]}.linux-{host}.tar.gz'
    fetch('https://go.dev/dl/' + archive.name, archive, LOCK['archives'][host], offline)
    directory = CACHE / f'go-{LOCK["version"]}-{host}'
    go = directory / 'go/bin/go'
    if not go.exists():
        extract(archive, directory)
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOROOT=str(directory / 'go'))
    actual = subprocess.check_output([str(go), 'version'], env=env, text=True).split()[2]
    if actual != 'go' + LOCK['version']:
        raise SystemExit('Cached compiler does not match the Go lock')
    env.setdefault('GOMODCACHE', str(ROOT / '.cache/go-mod'))
    env.setdefault('GOCACHE', str(ROOT / '.cache/go-build'))
    return go, env

def verify_binary(go, env, binary):
    line = subprocess.check_output([str(go), 'version', '-m', str(binary)], env=env, text=True).splitlines()[0]
    if line.split()[-1] != 'go' + LOCK['version']:
        raise SystemExit(f'Binary was not compiled with locked Go {LOCK["version"]}: {binary}')
