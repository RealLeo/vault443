#!/bin/bash
set -euo pipefail
# Never run this on the development host or an ordinary Linux desktop.
test -f /etc/vault443-fixture-guest
test "$(cat /sys/class/dmi/id/product_name)" = VirtualBox
test "$(id -u)" = 0
ip -4 -j address show dev fixture0 | jq -e '.[0].addr_info | any(.local == "192.0.2.1")' >/dev/null
install -d -m700 /fixture /opt/vault443-fixture/bin
install -m755 /home/vaultfixture/staging/xray /opt/vault443-fixture/bin/xray
install -m755 /home/vaultfixture/staging/e2e-fixture /opt/vault443-fixture/bin/e2e-fixture
for unit in web xray dns; do systemctl stop "vault443-fixture-$unit.service" 2>/dev/null || true; done
if ! test -f /fixture/ca.crt; then
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 -subj /CN=Vault443-Windows-Test-Root -keyout /fixture/ca.key -out /fixture/ca.crt >/fixture/certificate.log 2>&1
    openssl req -newkey rsa:2048 -nodes -subj /CN=vpn.e2e.invalid -keyout /fixture/server.key -out /fixture/server.csr >>/fixture/certificate.log 2>&1
    cat >/fixture/extensions <<'EOF'
subjectAltName=DNS:vpn.e2e.invalid,DNS:cloudflare-dns.com,DNS:web.e2e.example.com,DNS:web6.e2e.example.com,DNS:webdual.e2e.example.com,DNS:cp.cloudflare.com,DNS:www.gstatic.com,IP:1.1.1.1,IP:93.184.215.14,IP:2001:db8:66::14
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
EOF
    openssl x509 -req -in /fixture/server.csr -CA /fixture/ca.crt -CAkey /fixture/ca.key -CAcreateserial -out /fixture/server.crt -days 2 -sha256 -extfile /fixture/extensions >>/fixture/certificate.log 2>&1
    cat /proc/sys/kernel/random/uuid >/fixture/client.uuid
fi
for address in 1.1.1.1/32 203.0.113.1/32 93.184.215.14/32; do ip address replace "$address" dev lo; done
ip -6 address replace 2001:db8:66::14/128 dev lo
python3 - <<'PY'
import json,base64,secrets
from pathlib import Path
uuid=Path('/fixture/client.uuid').read_text().strip()
passwordFile=Path('/fixture/proxy.password')
if not passwordFile.exists(): passwordFile.write_text(secrets.token_hex(24))
password=passwordFile.read_text().strip()
config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'192.0.2.1','port':8443,'protocol':'vless','settings':{'clients':[{'id':uuid}],'decryption':'none'},'streamSettings':{'network':'tcp','security':'tls','tlsSettings':{'certificates':[{'certificateFile':'/fixture/server.crt','keyFile':'/fixture/server.key'}]}}}], 'outbounds':[{'protocol':'freedom','tag':'direct'}]}
config['inbounds'].extend([
 {'listen':'192.0.2.1','port':8444,'protocol':'trojan','settings':{'clients':[{'password':password}]},'streamSettings':{'network':'tcp','security':'tls','tlsSettings':{'certificates':[{'certificateFile':'/fixture/server.crt','keyFile':'/fixture/server.key'}]}}},
 {'listen':'192.0.2.1','port':8388,'protocol':'shadowsocks','settings':{'method':'aes-128-gcm','password':password,'network':'tcp,udp'}}])
Path('/fixture/server.json').write_text(json.dumps(config))
uri=f'vless://{uuid}@192.0.2.1:8443?security=tls&type=tcp&sni=vpn.e2e.invalid#Windows-Private-E2E'
Path('/home/vaultfixture/main-import.json').write_text(json.dumps([uri,'text','Windows fixture']))
ss='ss://'+base64.urlsafe_b64encode(('aes-128-gcm:'+password).encode()).decode().rstrip('=')+'@192.0.2.1:8388#Windows-Shadowsocks'
trojan=f'trojan://{password}@192.0.2.1:8444?security=tls&type=tcp&sni=vpn.e2e.invalid#Windows-Trojan'
Path('/fixture/main-subscription').write_text(base64.b64encode(('\n'.join([uri,trojan,ss])).encode()).decode())
Path('/fixture/dynamic-outline').write_text(json.dumps({'server':'192.0.2.1','server_port':8388,'password':password,'method':'aes-128-gcm','prefix':'V'}))
Path('/home/vaultfixture/main-profiles.json').write_text(json.dumps({'vless':uri,'trojan':trojan,'shadowsocks':ss,'outline':'ssconf://web.e2e.example.com/outline#Windows-Outline','subscription':'https://web.e2e.example.com/subscription'}))
PY
install -m644 /fixture/ca.crt /home/vaultfixture/ca.crt
chown vaultfixture:vaultfixture /home/vaultfixture/ca.crt /home/vaultfixture/main-import.json /home/vaultfixture/main-profiles.json
chmod 0600 /home/vaultfixture/main-import.json
systemd-run --unit=vault443-fixture-web --collect --property=Restart=on-failure /opt/vault443-fixture/bin/e2e-fixture
systemd-run --unit=vault443-fixture-xray --collect --property=Restart=on-failure /opt/vault443-fixture/bin/xray run -config /fixture/server.json
systemd-run --unit=vault443-fixture-dns --collect --property=Restart=on-failure /usr/sbin/dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces --listen-address=192.0.2.1,1.1.1.1,2001:db8:44::1 --address=/vpn.e2e.invalid/192.0.2.1 --address=/cloudflare-dns.com/1.1.1.1 --address=/#/93.184.215.14
echo 'Private Windows VPN fixture services started'
