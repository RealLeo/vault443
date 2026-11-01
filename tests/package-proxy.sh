#!/bin/bash
set -euo pipefail
test -f /.dockerenv
test "${VAULT443_PACKAGE_TEST:-}" = 1
test "${VAULT443_PROXY_E2E:-}" = 1
systemctl stop vault443.service
cp /var/lib/vault443/state.json /tmp/pre-outline-state.json
VAULT443_PACKAGE_PROXY_SEED=1 /src/.cache/proxy-e2e.test -test.run '^TestPackageProxyProfile$' -test.v
systemctl start vault443.service
python3 /src/tests/package-network-check.py connected
python3 - <<'PY'
import json
from pathlib import Path
state=json.loads(Path('/var/lib/vault443/state.json').read_text())
p=next(x for x in state['users']['11000']['profiles'] if x['id']==state['desired']['profileId'])
assert p['source']['lastAttempt'] > 0 and not p['source'].get('usingCached')
PY
nft list table inet vault443_outline > /results/outline-adapter-gate.txt
grep -q 'meta mark 0x564c5404' /results/outline-adapter-gate.txt
grep -q 'skuid root\|skuid 0' /results/outline-adapter-gate.txt
# ProtectControlGroups may give the service a cgroup namespace rooted at itself.
# The root+mark gate remains mandatory when no cgroup ancestry is visible.

pid=$(systemctl show -p MainPID --value vault443.service)
kill -KILL "$pid"
python3 /src/tests/package-network-check.py blocked
for _ in $(seq 1 100); do
  next=$(systemctl show -p MainPID --value vault443.service)
  if [ "$next" != 0 ] && [ "$next" != "$pid" ]; then break; fi
  sleep .1
done
python3 /src/tests/package-network-check.py connected
systemctl stop vault443.service
/usr/sbin/vault443d --boot-guard
nft delete table inet vault443_outline
python3 /src/tests/package-network-check.py blocked
install -m600 -o root -g root /tmp/pre-outline-state.json /var/lib/vault443/.restored-test-state
mv /var/lib/vault443/.restored-test-state /var/lib/vault443/state.json
systemctl start vault443.service
python3 /src/tests/package-network-check.py connected
echo 'PASS: packaged Outline, protected HTTPS refresh, private adapter gate and supervisor crash/recovery'
