#!/bin/bash
set -euo pipefail

# This script is only invoked by the isolated Docker runner. It never executes
# host ip/nft/systemd commands, and no network is attached to the container.
test -f /.dockerenv
test "${VAULT443_E2E_ISOLATED:-}" = 1
test -d /results
# A network-none Docker container starts with loopback only. Refuse bridged or
# host networking before installing certificates or changing any network state.
ip -j link show | jq -e 'length == 1 and .[0].ifname == "lo"' >/dev/null
mkdir -p /fixture /run/dbus /usr/lib/vault443 /var/lib/vault443-e2e /run/vault443-e2e
chmod 0700 /fixture /var/lib/vault443-e2e /run/vault443-e2e
install -m 0755 /src/.cache/xray/amd64/xray /usr/lib/vault443/xray

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -subj /CN=Vault443-E2E-Root \
  -keyout /fixture/ca.key -out /fixture/ca.crt >/results/cert.log 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=vpn.e2e.invalid \
  -keyout /fixture/server.key -out /fixture/server.csr >>/results/cert.log 2>&1
cat >/fixture/extensions <<'EOF'
subjectAltName=DNS:vpn.e2e.invalid,DNS:cloudflare-dns.com,DNS:web.e2e.example.com,DNS:web6.e2e.example.com,DNS:webdual.e2e.example.com,DNS:cp.cloudflare.com,DNS:www.gstatic.com,IP:1.1.1.1,IP:93.184.215.14,IP:2001:db8:66::14
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
EOF
openssl x509 -req -in /fixture/server.csr -CA /fixture/ca.crt -CAkey /fixture/ca.key \
  -CAcreateserial -out /fixture/server.crt -days 2 -sha256 \
  -extfile /fixture/extensions >>/results/cert.log 2>&1
install -m 0644 /fixture/ca.crt /usr/local/share/ca-certificates/vault443-e2e.crt
update-ca-certificates >/results/ca-install.log 2>&1

# Server is reachable solely by a veth pair inside this disposable container.
ip netns add fixture
ip link add e2euplink type veth peer name e2eserver
if [ "${VAULT443_REAL_SYSTEMD:-}" = 1 ]; then
  # PID1 tests keep the real NetworkManager running. This synthetic veth has
  # static fixture addressing, so do not let its automatic DHCP take it over.
  nmcli device set e2euplink managed no
fi
ip link set e2eserver netns fixture
ip address add 192.0.2.2/24 dev e2euplink
ip link set e2euplink up
ip route add default via 192.0.2.1 dev e2euplink
ip netns exec fixture ip link set lo up
ip netns exec fixture ip address add 192.0.2.1/24 dev e2eserver
ip netns exec fixture ip link set e2eserver up
ip netns exec fixture ip address add 1.1.1.1/32 dev lo
ip netns exec fixture ip address add 203.0.113.1/32 dev lo
ip netns exec fixture ip address add 93.184.215.14/32 dev lo
ip netns exec fixture ip -6 address add 2001:db8:66::14/128 dev lo
ip netns exec fixture "${VAULT443_E2E_FIXTURE_BINARY:-/src/.cache/e2e-fixture}" >/results/fixture.log 2>&1 &

cat >/fixture/server.json <<'EOF'
{
  "log": {"loglevel":"debug", "access":"/results/server-access.log", "error":"/results/server-error.log"},
  "inbounds": [{"listen":"0.0.0.0", "port":8443, "protocol":"vless",
    "settings":{"clients":[{"id":"11111111-2222-4333-8444-555555555555"}],"decryption":"none"},
    "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/fixture/server.crt","keyFile":"/fixture/server.key"}]}}
  }],
  "outbounds": [{"protocol":"freedom","tag":"direct"}]
}
EOF
# Fresh local REALITY identity; the target is the same isolated TLS/HTTP2 server.
/usr/lib/vault443/xray x25519 >/fixture/reality.keys
chmod 0600 /fixture/reality.keys
reality_private=$(awk '/^PrivateKey:/ { print $2 }' /fixture/reality.keys)
reality_public=$(awk '/^Password/ { print $3 }' /fixture/reality.keys)
test -n "$reality_private"
test -n "$reality_public"
jq --arg private "$reality_private" '.inbounds += [{
  listen:"192.0.2.1", port:8444, protocol:"vless",
  settings:{clients:[{id:"11111111-2222-4333-8444-555555555555",flow:"xtls-rprx-vision"}],decryption:"none"},
  streamSettings:{network:"tcp",security:"reality",realitySettings:{
    target:"1.1.1.1:443",serverNames:["vpn.e2e.invalid"],privateKey:$private,shortIds:["0123456789abcdef"]
  }}
}]' /fixture/server.json >/fixture/server.next.json
mv /fixture/server.next.json /fixture/server.json
printf 'vless://11111111-2222-4333-8444-555555555555@192.0.2.1:8444?security=reality&type=tcp&flow=xtls-rprx-vision&sni=vpn.e2e.invalid&fp=chrome&pbk=%s&sid=0123456789abcdef#Private-REALITY\n' "$reality_public" >/fixture/reality.uri
chmod 0600 /fixture/reality.uri
unset reality_private reality_public
if [ "${VAULT443_PROXY_E2E:-}" = 1 ]; then
  python3 /src/tests/e2e/proxy-fixture.py
  if [ "${VAULT443_QUIC_E2E:-}" = 1 ]; then ip netns exec fixture /src/.cache/quic-fixture server >/results/quic-server.log 2>&1 & fi
  ip netns exec fixture /usr/lib/vault443/xray run -config /fixture/outline-exit.json >/results/outline-exit.log 2>&1 &
  install -m755 /src/.cache/outline/amd64/vault443-outline /usr/lib/vault443/vault443-outline
  ip netns exec fixture /src/.cache/outline/testserver >/results/outline-fixture.log 2>&1 &
fi
ip netns exec fixture /usr/lib/vault443/xray run -config /fixture/server.json >/results/server.log 2>&1 &

if [ "${VAULT443_REAL_SYSTEMD:-}" = 1 ]; then
  test "$(cat /proc/1/comm)" = systemd
  systemctl is-active --quiet dbus.service systemd-resolved.service NetworkManager.service
else
  dbus-daemon --system --fork --nopidfile
  install -d -o systemd-resolve -g systemd-resolve -m 0755 /run/systemd/resolve
  /usr/lib/systemd/systemd-resolved >/results/resolved.log 2>&1 &
fi
for attempt in $(seq 1 50); do
  if resolvectl status >/results/resolved-status-before.txt 2>&1; then break; fi
  sleep 0.1
done
resolvectl status >/results/resolved-status-before.txt

if [ "${VAULT443_WORKVPN_E2E:-}" = 1 ]; then
  /bin/bash /src/tests/e2e/workvpn-fixture.sh
fi
if [ "${VAULT443_WIREGUARD_E2E:-}" = 1 ]; then
  install -m755 /src/.cache/amneziawg/amd64/amneziawg-go /usr/lib/vault443/amneziawg-go
  python3 /src/tests/e2e/wireguard-fixture.py
fi

set +e
if [ "${VAULT443_PACKAGE_NETWORK:-}" = 1 ]; then
  /bin/bash /src/tests/package-lifecycle.sh 2>&1 | tee /results/package-lifecycle.log
  result=${PIPESTATUS[0]}
else
  "${VAULT443_E2E_TEST_BINARY:-/src/.cache/e2e.test}" -test.v -test.run "${VAULT443_E2E_TEST_PATTERN:-^TestRealVLESS}" -test.timeout="${VAULT443_E2E_TIMEOUT:-240s}" 2>&1 | tee /results/e2e.log
  result=${PIPESTATUS[0]}
fi
ip -j -4 rule show >/results/rules-after.json
ip -j -4 route show table all >/results/routes-after.json
nft -j list ruleset >/results/nft-after.json
resolvectl status >/results/resolved-status-after.txt
exit "$result"
