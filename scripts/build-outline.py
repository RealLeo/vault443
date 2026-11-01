#!/usr/bin/env python3
"""Build the pinned private Outline adapter with the shared locked Go toolchain."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import toolchain as tc

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'packaging/outline-lock.json').read_text())
CACHE = ROOT / '.cache/outline'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=['amd64', 'arm64'])
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('awg_build', ROOT / 'scripts/build-amneziawg.py')
    awg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(awg)
    go, env = tc.ensure(offline=args.offline)
    toolchain = Path(env['GOROOT']).parent
    source = ROOT / 'helpers/outline'
    env.update(GOMODCACHE=str(CACHE / 'modules'), GOCACHE=str(CACHE / 'build-cache'),
               CGO_ENABLED='0', GOOS='linux', GOARCH=args.architecture)
    if args.offline:
        env.update(GOPROXY='off', GOSUMDB='off')
    else:
        subprocess.run([str(go), 'mod', 'download'], cwd=source, env=env, check=True)
    for item in LOCK['modules']:
        modulezip = CACHE / 'modules/cache/download' / item['module'] / '@v' / (item['version'] + '.zip')
        if hashlib.sha256(modulezip.read_bytes()).hexdigest() != item['zipSha256']:
            raise SystemExit('Pinned Outline source archive checksum mismatch: ' + item['module'])
    subprocess.run([str(go), 'mod', 'verify'], cwd=source, env=env, check=True)
    version = (ROOT / 'VERSION').read_text().strip()
    out = CACHE / args.architecture
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'vault443-outline'
    subprocess.run([str(go), 'build', '-mod=readonly', '-buildvcs=false', '-trimpath',
                    '-ldflags=-s -w -X main.version=' + version, '-o', str(binary), '.'],
                   cwd=source, env=env, check=True)
    tc.verify_binary(go, env, binary)
    licenses = out / 'licenses'
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(toolchain / 'go/LICENSE', licenses / 'Go-LICENSE')
    modules = []
    for module in awg.modules(go, env, source):
        if module['Path'].startswith('vault443'):
            continue
        directory = Path(module['Dir'])
        names = []
        for file in directory.iterdir():
            if file.is_file() and file.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                name = module['Path'].replace('/', '_') + '--' + file.name
                shutil.copyfile(file, licenses / name)
                names.append(name)
        if not names:
            raise SystemExit('Dependency license missing: ' + module['Path'])
        modules.append({'module': module['Path'], 'version': module['Version'], 'licenses': names})
    (licenses / 'modules.json').write_text(json.dumps(modules, indent=2) + '\n')
    manifest = dict(LOCK, goVersion=tc.LOCK['version'], architecture=args.architecture, productVersion=version,
                    goSumSha256=hashlib.sha256((source / 'go.sum').read_bytes()).hexdigest(),
                    binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (out / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Outline adapter', version, args.architecture, manifest['binarySha256'])

if __name__ == '__main__':
    main()
