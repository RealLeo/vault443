#!/bin/bash
set -euo pipefail
test -f /.dockerenv
test "${VAULT443_PACKAGE_TEST:-}" = 1
test "${VAULT443_E2E_ISOLATED:-}" = 1
test "$(cat /proc/1/comm)" = systemd
export VAULT443_WORKVPN_E2E=1 VAULT443_WIREGUARD_E2E=1 VAULT443_PACKAGE_WIREGUARD=1
systemctl stop vault443.service
python3 /src/tests/e2e/wireguard-fixture.py
VAULT443_PACKAGE_WIREGUARD_SEED=1 /src/.cache/workvpn-e2e.test -test.run '^TestPackageWireGuardProfiles$' -test.v
cp /var/lib/vault443/work-vpn.json /tmp/wg-work-before.json
systemctl start vault443.service
python3 /src/tests/package-workvpn-check.py connected
old_pid=$(systemctl show -p MainPID --value vault443.service)
rm -f /tmp/work-monitor-ready /tmp/work-monitor-stop
python3 /src/tests/package-workvpn-check.py monitor >/tmp/wg-guard-monitor.log 2>&1 &
monitor=$!
for _ in $(seq 1 50); do test ! -f /tmp/work-monitor-ready || break; sleep .1; done
test -f /tmp/work-monitor-ready
kill -KILL "$old_pid"
for _ in $(seq 1 100); do
  new_pid=$(systemctl show -p MainPID --value vault443.service)
  if [ "$new_pid" != 0 ] && [ "$new_pid" != "$old_pid" ]; then break; fi
  sleep .1
done
python3 /src/tests/package-workvpn-check.py connected
touch /tmp/work-monitor-stop
wait "$monitor"
cat /tmp/wg-guard-monitor.log
systemctl restart vault443.service
python3 /src/tests/package-workvpn-check.py connected
python3 /src/tests/package-network-check.py connected
cmp /var/lib/vault443/work-vpn.json /tmp/wg-work-before.json
echo 'PASS: hardened systemd WireGuard/AmneziaWG, kernel-interface recovery after crash, preserved state and continuous work-route protection'
