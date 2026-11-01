#!/bin/bash
set -euo pipefail
trap 'test ! -f /tmp/rejected-install.log || tail -n 10 /tmp/rejected-install.log' ERR
export LANG=C.UTF-8
test -f /.dockerenv
test "${VAULT443_PACKAGE_TEST:-}" = 1
test "${VAULT443_PACKAGE_NETWORK:-}" = 1
test "$(cat /proc/1/comm)" = systemd
systemctl is-active --quiet NetworkManager.service systemd-resolved.service dbus.service
version=$(cat /src/VERSION)
package=/tmp/vault443_${version}_amd64.deb
cp /src/dist/vault443_${version}_amd64.deb "$package"
baseline=/src/dist/vault443_1.3.0_amd64.deb
nft add table inet unrelated_test
# Refuse pre-1.0 stores before installing binaries or touching private data.
install -d -m700 /var/lib/vless-terminal
printf '{"private":"unchanged"}' >/var/lib/vless-terminal/state.json
cp /var/lib/vless-terminal/state.json /tmp/untouched-state
if dpkg -i "$package" >/tmp/rejected-install.log 2>&1; then exit 1; fi
grep -q 'Complete the transition' /tmp/rejected-install.log
cmp /var/lib/vless-terminal/state.json /tmp/untouched-state
test ! -e /usr/sbin/vault443d
rm /var/lib/vless-terminal/state.json
rmdir /var/lib/vless-terminal
# A pending transaction blocks installation even when no old client is installed.
install -d -m700 /var/lib/vault443-migration
printf '{}' >/var/lib/vault443-migration/active.json
if dpkg -i "$package" >/tmp/rejected-install.log 2>&1; then exit 1; fi
grep -q 'unfinished migration' /tmp/rejected-install.log
rm /var/lib/vault443-migration/active.json
# Completed recovery backups are private and must be left alone by new packages.
install -d -m700 /var/lib/vault443-migration/backups/completed
printf retained >/var/lib/vault443-migration/backups/completed/marker
chmod 600 /var/lib/vault443-migration/backups/completed/marker
useradd -u 11000 -m vaultoperator
useradd -u 11001 -m vaultcolleague
# Defer the baseline startup until the synthetic profiles are present.
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
dpkg -i "$baseline"
usermod -aG vault443 vaultoperator
usermod -aG vault443 vaultcolleague
initial_gid=$(getent group vault443 | cut -d: -f3)
install -d -m700 /var/lib/vault443
python3 - <<'PY'
import json, os, time
from pathlib import Path
profile={'id':'stable-profile','name':'Private test profile','server':'192.0.2.1','port':8443,
         'uuid':'11111111-2222-4333-8444-555555555555','transport':'tcp','security':'tls',
         'sni':'vpn.e2e.invalid','iconId':'vault-door','debugLogging':True}
subscription={'id':'stable-subscription','name':'Saved subscription','url':'https://subscription.invalid/list',
              'updatedAt':int(time.time()),'lastAttempt':int(time.time())}
profile['kind']='vless'
state={'version':3,'users':{'11000':{'profiles':[profile],'subscriptions':[subscription]},
                          '11001':{'profiles':[dict(profile,id='private-second')],'subscriptions':[]}},
       'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
       'desired':{'uid':11000,'profileId':'stable-profile'},'boot':{'uid':11000,'profileId':'stable-profile'}}
p=Path('/var/lib/vault443/state.json');p.write_text(json.dumps(state));p.chmod(0o600)
p=Path('/var/lib/vault443/private-marker');p.write_text('retained-data');p.chmod(0o600)
Path('/tmp/original-state.json').write_text(json.dumps(state))
PY
export VAULT443_WORKVPN_E2E=1
/bin/bash /src/tests/e2e/workvpn-fixture.sh
VAULT443_PACKAGE_WORK_SEED=1 \
  /src/.cache/workvpn-e2e.test -test.run '^TestPackageWorkProfiles$' -test.v
cp /var/lib/vault443/work-vpn.json /tmp/work-before-upgrade.json
systemctl start vault443-guard.service vault443.service
python3 /src/tests/package-network-check.py connected
python3 /src/tests/package-workvpn-check.py connected
busctl --xml-interface introspect org.vault443.Service1 /org/vault443/Service1 > /tmp/api-before.xml
old_pid=$(systemctl show -p MainPID --value vault443.service)
# Allow the real package scripts to restart the active daemon during upgrade.
rm /usr/sbin/policy-rc.d
python3 /src/tests/package-network-check.py monitor >/tmp/guard-monitor.log 2>&1 &
monitor=$!
for _ in $(seq 1 50); do test ! -f /tmp/guard-monitor-ready || break; sleep .1; done
test -f /tmp/guard-monitor-ready
dpkg -i "$package"
new_pid=$(systemctl show -p MainPID --value vault443.service)
busctl --xml-interface introspect org.vault443.Service1 /org/vault443/Service1 > /tmp/api-after.xml
python3 - <<'PYAPI'
import xml.etree.ElementTree as E
def methods(path):
 root=E.parse(path).getroot()
 return {(i.get('name'), m.get('name')): [(a.get('type'),a.get('direction','in')) for a in m.findall('arg')]
         for i in root.findall('interface') for m in i.findall('method')}
before,after=methods('/tmp/api-before.xml'),methods('/tmp/api-after.xml')
assert all(after.get(k)==v for k,v in before.items()), '1.0 D-Bus method removed or signature changed'
assert ('org.vault443.Service1','PrepareOpenVPNImport') in after
assert ('org.vault443.Service1','PrepareWorkImport') in after
assert ('org.vault443.Service1','RequestWorkConnect') in after
assert ('org.vault443.Service1','CancelSwitch') in after
PYAPI
test "$old_pid" != "$new_pid"
python3 /src/tests/package-network-check.py connected
python3 /src/tests/package-workvpn-check.py connected
touch /tmp/guard-monitor-stop
wait "$monitor"
cat /tmp/guard-monitor.log
systemctl is-active --quiet NetworkManager.service systemd-resolved.service vault443.service
test "$(getent group vault443 | cut -d: -f3)" = "$initial_gid"
getent group vault443 | grep -q 'vaultoperator,vaultcolleague'
test ! -e /etc/xdg/autostart/vault443-migrate.desktop
python3 - <<'PY'
import json,os
from pathlib import Path
a=json.loads(Path('/tmp/original-state.json').read_text()); b=json.loads(Path('/var/lib/vault443/state.json').read_text())
assert not Path('/var/lib/vault443/state.v2.backup.json').exists(), 'patch release unexpectedly migrated v3'
assert a==b, 'saved profiles, subscriptions or boot/desired connection changed'

assert Path('/var/lib/vault443/private-marker').read_text()=='retained-data'
assert Path('/var/lib/vault443-migration/backups/completed/marker').read_text()=='retained'
assert os.stat('/var/lib/vault443/state.json').st_mode & 0o777 == 0o600
old_work=json.loads(Path('/tmp/work-before-upgrade.json').read_text())
new_work=json.loads(Path('/var/lib/vault443/work-vpn.json').read_text())
assert old_work['version']==2 and new_work==old_work, '1.3.0 work profiles or desired sessions changed'
assert not Path('/var/lib/vault443/work-vpn.v1.backup.json').exists(), 'unexpected schema migration during patch update'
PY
# Reinstall is a normal 1.x operation and still resumes the selected connection.
dpkg -i "$package"
python3 /src/tests/package-network-check.py connected
/usr/sbin/vault443d --check
/usr/sbin/vault443d --version
systemd-analyze verify /usr/lib/systemd/system/vault443.service /usr/lib/systemd/system/vault443-guard.service
mkdir -m700 /tmp/lifecycle-runtime
XDG_RUNTIME_DIR=/tmp/lifecycle-runtime QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software \
  timeout 15s /usr/bin/vault443 --demo --screenshot /tmp/installed-gui.png
test -s /tmp/installed-gui.png
/bin/bash /src/tests/package-workvpn.sh
/bin/bash /src/tests/package-wireguard.sh
if [ "${VAULT443_PROXY_E2E:-}" = 1 ]; then /bin/bash /src/tests/package-proxy.sh; fi
dpkg --purge vault443
test -f /var/lib/vault443/private-marker
nft list table inet unrelated_test >/dev/null
if nft list table inet vault443 >/dev/null 2>&1; then exit 1; fi
if nft list table inet vault443_work >/dev/null 2>&1; then exit 1; fi
test "$(ip -j link show | jq '[.[] | select(.ifname | startswith("v443w"))] | length')" = 0
for family in 4 6; do
  ip -N -j -"$family" route show table all | python3 -c '
import json,sys
for r in json.load(sys.stdin):
    try: table=int(r.get("table",254))
    except (TypeError,ValueError): continue
    assert table != 52789 and table not in range(52783,52788) and table not in range(52800,52833), "owned work route survived removal"
'
done
# Fresh APT install uses the new package, without any previous application state.
mv /var/lib/vault443 /tmp/preserved-vault443
apt-get -y install "$package"
systemctl is-active --quiet vault443.service
test "$(stat -c '%a:%U' /var/lib/vault443)" = 700:root
test ! -e /etc/xdg/autostart/vault443-migrate.desktop
dpkg --purge vault443
test -f /tmp/preserved-vault443/private-marker
nft list table inet unrelated_test >/dev/null
systemctl is-active --quiet NetworkManager.service systemd-resolved.service dbus.service
echo "PASS: 1.3.0 to 1.3.1 upgrade, active VLESS/work connections, unchanged work schema, continuous guard, preserved multiuser state/GID, reinstall, purge and fresh APT installation"
