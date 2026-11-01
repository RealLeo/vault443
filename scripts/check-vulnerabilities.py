#!/usr/bin/env python3
"""Release gate: scan shipped Go entry points with the locked compiler.

The AWG module includes HTTP examples and an SDK library that are not linked into
its standalone executable. Scan '.' there, not every upstream example in './...'.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import toolchain

ROOT = toolchain.ROOT
OUTPUT = ROOT / '.cache/security'
TOOL_VERSION = 'v1.9.0'
AWG = json.loads((ROOT / 'packaging/amneziawg-lock.json').read_text())
SOURCE = ROOT / '.cache/amneziawg' / ('amneziawg-go-' + AWG['commit'])
TARGETS = [('service', ROOT, './...', ROOT / '.cache/go-mod'),
           ('outline', ROOT / 'helpers/outline', './...', ROOT / '.cache/outline/modules'),
           ('amneziawg', SOURCE, '.', ROOT / '.cache/amneziawg/modules')]

def fingerprint():
    files = [ROOT / x for x in ['VERSION', 'go.mod', 'go.sum', 'packaging/go-toolchain-lock.json',
                               'packaging/amneziawg-lock.json', 'packaging/outline-lock.json',
                               'helpers/outline/go.mod', 'helpers/outline/go.sum', 'scripts/check-vulnerabilities.py']]
    for directory in ['cmd', 'internal', 'helpers/outline', 'tests/e2e']:
        files.extend((ROOT / directory).rglob('*.go'))
    h = hashlib.sha256()
    for path in sorted(set(files)):
        h.update(str(path.relative_to(ROOT)).encode()); h.update(b'\0'); h.update(path.read_bytes())
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true', help='Require a passing report for these exact sources, at most 24 hours old')
    args = parser.parse_args()
    report_path = OUTPUT / 'report.json'
    if args.verify:
        report = json.loads(report_path.read_text())
        if report.get('sourceSha256') != fingerprint() or report.get('goVersion') != toolchain.LOCK['version'] or report.get('govulncheck') != TOOL_VERSION or not 0 <= time.time() - report.get('checkedAt', 0) <= 86400 or report.get('results') != {x[0]: 0 for x in TARGETS}:
            raise SystemExit('Vulnerability gate failed or stale: run python3 scripts/check-vulnerabilities.py')
        print('Vulnerability gate: current sources passed with locked Go')
        return
    go, env = toolchain.ensure()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    report_path.unlink(missing_ok=True)
    env.update(PATH=str(go.parent) + os.pathsep + env['PATH'], GOBIN=str(OUTPUT / 'bin'))
    tool = OUTPUT / 'bin/govulncheck'
    if not tool.is_file() or 'golang.org/x/vuln\t' + TOOL_VERSION not in subprocess.check_output([str(go), 'version', '-m', str(tool)], env=env, text=True):
        subprocess.run([str(go), 'install', 'golang.org/x/vuln/cmd/govulncheck@' + TOOL_VERSION], env=env, cwd=ROOT, check=True)
    results = {}
    for name, source, pattern, cache in TARGETS:
        print('Scanning', name, flush=True)
        target_env = dict(env, GOMODCACHE=str(cache), GOOS='linux', GOARCH='amd64')
        with (OUTPUT / (name + '.log')).open('w') as log:
            result = subprocess.run([str(tool), pattern], cwd=source, env=target_env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        results[name] = result.returncode
        print(name, 'PASS' if result.returncode == 0 else 'FAIL — inspect ' + str(OUTPUT / (name + '.log')), flush=True)
    report_path.write_text(json.dumps(dict(checkedAt=time.time(), goVersion=toolchain.LOCK['version'], govulncheck=TOOL_VERSION, sourceSha256=fingerprint(), results=results), indent=2) + '\n')
    if any(results.values()):
        raise SystemExit('Reachable vulnerability or scan failure blocks release')

if __name__ == '__main__':
    main()
