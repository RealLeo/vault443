#!/bin/bash
set -euo pipefail
# Only the project-private VirtualBox fixture guest may configure these servers.
test -f /etc/vault443-fixture-guest
test "$(cat /sys/class/dmi/id/product_name)" = VirtualBox
test "$(id -u)" = 0
ip -4 -j address show dev fixture0 | jq -e '.[0].addr_info | any(.local == "192.0.2.1")' >/dev/null
test -r /fixture/ca.crt -a -r /fixture/ca.key -a -r /fixture/server.crt -a -r /fixture/server.key
install -d -m700 /fixture/openvpn
for unit in openvpn openvpn-dns openvpn-web; do systemctl stop "vault443-fixture-$unit.service" 2>/dev/null || true; done
if ! test -f /fixture/openvpn/client.crt || ! openssl x509 -checkend 3600 -noout -in /fixture/openvpn/client.crt >/dev/null; then
    openssl req -newkey rsa:2048 -nodes -subj /CN=vault443-windows-openvpn-client -keyout /fixture/openvpn/client.key -out /fixture/openvpn/client.csr >/fixture/openvpn/certificate.log 2>&1
    printf '%s\n' 'extendedKeyUsage=clientAuth' 'keyUsage=digitalSignature,keyEncipherment' 'basicConstraints=CA:FALSE' >/fixture/openvpn/extensions
    openssl x509 -req -in /fixture/openvpn/client.csr -CA /fixture/ca.crt -CAkey /fixture/ca.key -CAcreateserial -out /fixture/openvpn/client.crt -days 2 -sha256 -extfile /fixture/openvpn/extensions >>/fixture/openvpn/certificate.log 2>&1
fi
cat >/fixture/openvpn/server.conf <<'EOF'
local 192.0.2.1
port 1194
proto udp
dev v443ovpn
dev-type tun
topology subnet
server 10.77.0.0 255.255.255.0
server-ipv6 fd77:443::/64
ca /fixture/ca.crt
cert /fixture/server.crt
key /fixture/server.key
dh none
remote-cert-tls client
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
keepalive 5 25
persist-key
persist-tun
tun-mtu 1400
push "route 10.77.8.0 255.255.255.0"
push "route-ipv6 fd77:443:8::/64"
push "dhcp-option DNS 10.77.0.1"
push "dhcp-option DOMAIN-ROUTE corp.openvpn.test"
verb 3
disable-dco
EOF
chmod 600 /fixture/openvpn/*
ip address replace 10.77.8.10/32 dev lo
ip -6 address replace fd77:443:8::10/128 dev lo
systemd-run --unit=vault443-fixture-openvpn --collect --property=Restart=on-failure /usr/sbin/openvpn --config /fixture/openvpn/server.conf
for _ in {1..50}; do if ip -4 address show dev v443ovpn 2>/dev/null | grep -q 10.77.0.1; then break; fi; sleep .1; done
ip -4 address show dev v443ovpn | grep -q 10.77.0.1
systemd-run --unit=vault443-fixture-openvpn-dns --collect --property=Restart=on-failure /usr/sbin/dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces --listen-address=10.77.0.1 --address=/corp.openvpn.test/10.77.8.10 --address=/corp.openvpn.test/fd77:443:8::10 --address=/#/93.184.215.14
cat >/fixture/openvpn/web.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, socket, threading
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'marker':'openvpn-e2e-ok','peer':self.client_address[0]}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
class V6(ThreadingHTTPServer):address_family=socket.AF_INET6
for server in [ThreadingHTTPServer(('10.77.8.10',8080),Handler),V6(('fd77:443:8::10',8080),Handler)]:
    threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
PY
systemd-run --unit=vault443-fixture-openvpn-web --collect --property=Restart=on-failure /usr/bin/python3 /fixture/openvpn/web.py
python3 - <<'PY'
from pathlib import Path
import json,os
p=Path('/fixture/openvpn')
text='''client
proto udp
remote 192.0.2.1 1194
dev tun
nobind
persist-key
remote-cert-tls server
verify-x509-name vpn.e2e.invalid name
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tun-mtu 1400
verb 3
'''
for kind,source in [('ca',Path('/fixture/ca.crt')),('cert',p/'client.crt'),('key',p/'client.key')]:
    text+=f'<{kind}>\n'+source.read_text().strip()+f'\n</{kind}>\n'
for suffix,body in [('',text),('-full',text+'redirect-gateway def1 ipv6\n')]:
    target=Path('/home/vaultfixture/openvpn'+suffix+'.ovpn');target.write_text(body);os.chmod(target,0o600)
    payload=Path('/home/vaultfixture/openvpn'+suffix+'-import.json');payload.write_text(json.dumps([json.dumps([{'name':'Vault443 Fixture openvpn'+suffix,'content':body}])]));os.chmod(payload,0o600)
PY
chown vaultfixture:vaultfixture /home/vaultfixture/openvpn*.ovpn /home/vaultfixture/openvpn*-import.json
echo 'Private OpenVPN fixture ready: UDP 192.0.2.1:1194, service 10.77.8.10:8080, DNS corp.openvpn.test'
