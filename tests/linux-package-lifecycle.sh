#!/bin/bash
set -euo pipefail
test -f /.dockerenv
test "${VAULT443_PACKAGE_TEST:-}" = 1
test "$(cat /proc/1/comm)" = systemd
target=${VAULT443_DISTRO:?}
package=${VAULT443_DISTRO_PACKAGE:?}
install_package() {
  case "$target" in
    debian13|ubuntu24|ubuntu26) dpkg -i "$package";;
    fedora44) rpm -U --replacepkgs "$package";;
    arch) pacman -U --noconfirm "$package";;
  esac
}
remove_package() {
  case "$target" in
    debian13|ubuntu24|ubuntu26) dpkg --purge vault443;;
    fedora44) rpm -e vault443;;
    arch) pacman -R --noconfirm vault443;;
  esac
}
nft add table inet unrelated_test
rm -f /usr/sbin/policy-rc.d
# The network fixture starts its server from these cached binaries before the
# package is installed. Unlink only those unowned fixture copies; pacman rightly
# refuses to overwrite pre-existing files. The running fixture keeps its inode.
rm -f /usr/lib/vault443/xray /usr/lib/vault443/vault443-outline
install_package
systemctl stop vault443.service
getent group vault443
useradd -u 11000 -m vaultoperator
useradd -u 11001 -m vaultcolleague
vault443-access vaultoperator
vault443-access vaultcolleague
getent group vault443 > /tmp/group-before
install -d -m700 /var/lib/vault443
python3 - <<'PY'
import json
from pathlib import Path
profile={'id':'stable-profile','kind':'vless','name':'Synthetic distro test','server':'192.0.2.1','port':8443,
         'uuid':'11111111-2222-4333-8444-555555555555','transport':'tcp','security':'tls',
         'sni':'vpn.e2e.invalid','iconId':'vault-door','debugLogging':True}
state={'version':3,'users':{'11000':{'profiles':[profile],'subscriptions':[]},
                          '11001':{'profiles':[dict(profile,id='private-second')],'subscriptions':[]}},
       'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
       'desired':{'uid':11000,'profileId':'stable-profile'},'boot':{'uid':11000,'profileId':'stable-profile'}}
p=Path('/var/lib/vault443/state.json');p.write_text(json.dumps(state));p.chmod(0o600)
Path('/tmp/saved-state.json').write_text(json.dumps(state))
PY
systemctl enable --now vault443-guard.service vault443.service
python3 /src/tests/package-network-check.py connected
old_pid=$(systemctl show -p MainPID --value vault443.service)
python3 /src/tests/package-network-check.py monitor >/results/guard-monitor.log 2>&1 &
monitor=$!
for _ in $(seq 1 50); do test ! -f /tmp/guard-monitor-ready || break; sleep .1; done
test -f /tmp/guard-monitor-ready
install_package
new_pid=$(systemctl show -p MainPID --value vault443.service)
test "$old_pid" != "$new_pid"
python3 /src/tests/package-network-check.py connected
touch /tmp/guard-monitor-stop
wait "$monitor"
cat /results/guard-monitor.log
getent group vault443 > /tmp/group-after
cmp /tmp/group-before /tmp/group-after
python3 - <<'PY'
import json,os
assert json.load(open('/tmp/saved-state.json')) == json.load(open('/var/lib/vault443/state.json'))
assert os.stat('/var/lib/vault443/state.json').st_mode & 0o777 == 0o600
PY
vault443d --check
vault443d --version
systemd-analyze verify /usr/lib/systemd/system/vault443.service /usr/lib/systemd/system/vault443-guard.service
for path in /usr/sbin/ip /usr/sbin/nft /usr/sbin/openvpn /usr/bin/wg /usr/bin/resolvectl /usr/sbin/vault443d; do test -x "$path"; done
for language in en ru; do
  LANGUAGE=$language QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software \
    timeout 20s vault443 --demo --screenshot "/results/installed-$language.png"
  test -s "/results/installed-$language.png"
done
# These exercise the actual packaged engines inside the existing network fixture.
export VAULT443_WORKVPN_E2E=1
/bin/bash /src/tests/package-proxy.sh
/bin/bash /src/tests/package-workvpn.sh
/bin/bash /src/tests/package-wireguard.sh
remove_package
systemctl is-active --quiet NetworkManager.service systemd-resolved.service
test -f /var/lib/vault443/state.json
nft list table inet unrelated_test >/dev/null
if nft list table inet vault443 >/dev/null 2>&1; then exit 1; fi
if nft list table inet vault443_work >/dev/null 2>&1; then exit 1; fi
if nft list table inet vault443_outline >/dev/null 2>&1; then exit 1; fi
test ! -e /usr/bin/vault443
test ! -e /usr/sbin/vault443d
if systemctl is-enabled --quiet vault443.service; then exit 1; fi
echo "PASS: $target native package: install, active reinstall, private data, guard, engines, removal"
