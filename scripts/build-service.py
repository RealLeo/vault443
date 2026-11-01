#!/usr/bin/env python3
"""Build the supervisor and record the actual compiler and binary identity."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import toolchain

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('architecture', choices=['amd64', 'arm64'])
p.add_argument('output', type=Path)
args = p.parse_args()
go, env = toolchain.ensure()
env.update(CGO_ENABLED='0', GOOS='linux', GOARCH=args.architecture, GOPROXY='off')
args.output.mkdir(parents=True, exist_ok=True)
binary = args.output / 'vault443d'
subprocess.run([str(go), 'build', '-mod=readonly', '-buildvcs=false', '-trimpath', '-ldflags=-s -w', '-o', str(binary.resolve()), './cmd/vault443d'], cwd=toolchain.ROOT, env=env, check=True)
toolchain.verify_binary(go, env, binary)
manifest = dict(goVersion=toolchain.LOCK['version'], architecture=args.architecture,
                productVersion=(toolchain.ROOT / 'VERSION').read_text().strip(),
                binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                goSumSha256=hashlib.sha256((toolchain.ROOT / 'go.sum').read_bytes()).hexdigest())
(args.output / 'vault443d.build.json').write_text(json.dumps(manifest, indent=2) + '\n')
shutil.copyfile(Path(env['GOROOT']) / 'LICENSE', args.output / 'Go-LICENSE')
