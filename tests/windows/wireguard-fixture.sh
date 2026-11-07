#!/bin/bash
set -euo pipefail
# This changes only the explicitly provisioned, isolated fixture guest.
test -f /etc/vault443-fixture-guest
test "$(cat /sys/class/dmi/id/product_name)" = VirtualBox
test "$(id -u)" = 0
ip -4 -j address show dev fixture0 | jq -e '.[0].addr_info | any(.local == "192.0.2.1")' >/dev/null
umask 077
install -d -m700 /fixture/wireguard /opt/vault443-fixture/bin
install -m755 /home/vaultfixture/staging/amneziawg-go /opt/vault443-fixture/bin/amneziawg-go
for service in awg wg-web wg-dns; do systemctl stop "vault443-fixture-$service.service" 2>/dev/null || true; done
# The second peer shares one client interface/address pool with the first.
# Its source-specific reply tables must precede main (priority 32766).
# Exact cleanup (also safe before reprovisioning):
# ip -4 rule del priority 10482 from 198.19.46.0/24 table 44482
# ip -6 rule del priority 10482 from 2001:db8:82::/64 table 44482
# ip -4 route flush table 44482; ip -6 route flush table 44482
ip -4 rule del priority 10482 from 198.19.46.0/24 table 44482 2>/dev/null || true
ip -6 rule del priority 10482 from 2001:db8:82::/64 table 44482 2>/dev/null || true
for iface in v443srvwg v443srvwg3 v443srvawg; do ip link delete "$iface" 2>/dev/null || true; done
python3 - <<'PY'
import base64,json,socket,subprocess,time
from pathlib import Path
root=Path('/fixture/wireguard');clients=Path('/home/vaultfixture/wireguard');clients.mkdir(exist_ok=True,mode=0o700)
def run(*args,input=None):return subprocess.check_output(args,input=input,stderr=subprocess.PIPE)
def pair(name):
 p=root/(name+'.key')
 if not p.exists():p.write_bytes(run('wg','genkey'))
 private=p.read_text().strip();public=run('wg','pubkey',input=(private+'\n').encode()).decode().strip()
 return private,public
client,client_public=pair('client');awg_client,awg_public=pair('awg-client');psk=pair('psk')[0]
params={'Jc':'2','Jmin':'40','Jmax':'64','S1':'16','S2':'17','S3':'18','S4':'19','H1':'101-110','H2':'201-210','H3':'301-310','H4':'401-410','I1':'<b 0xaabb><r 8>','HeaderProtectionKey':pair('header')[0],'ContentPaddingAddition':'0-8','RandomTrailers':'true','DisableCookies':'false'}
publics={}
for name,kind,port,subnet in [('v443srvwg','wireguard',51820,80),('v443srvawg','amneziawg',51821,81),('v443srvwg3','wireguard',51822,82)]:
 private,public=pair(name);publics[subnet]=public
 peer_public=awg_public if kind=='amneziawg' else client_public
 peer_ips=f'198.19.{subnet-36}.2/32,2001:db8:{subnet}::2/128'
 if subnet==82:peer_ips+=',198.19.44.2/32,2001:db8:80::2/128'
 if kind=='wireguard':
  run('ip','link','add',name,'type','wireguard')
  configuration=root/(name+'.conf');configuration.write_text(f'[Interface]\nPrivateKey = {private}\nListenPort = {port}\n[Peer]\nPublicKey = {peer_public}\nPresharedKey = {psk}\nAllowedIPs = {peer_ips}\n')
  run('wg','setconf',name,str(configuration))
 else:
  run('systemd-run','--unit=vault443-fixture-awg','--collect','--property=Restart=on-failure','/opt/vault443-fixture/bin/amneziawg-go','--foreground',name)
  fields={'HeaderProtectionKey':'header_protection_key','ContentPaddingAddition':'content_padding_addition','RandomTrailers':'random_trailers','DisableCookies':'disable_cookies'}
  text='private_key='+base64.b64decode(private).hex()+f'\nlisten_port={port}\n'
  for key,value in params.items():
   if key=='HeaderProtectionKey':value=base64.b64decode(value).hex()
   if value in ('true','false'):value='1' if value=='true' else '0'
   text+=fields.get(key,key.lower())+'='+value+'\n'
  text+='public_key='+base64.b64decode(peer_public).hex()+'\npreshared_key='+base64.b64decode(psk).hex()+'\n'
  text+=''.join('allowed_ip='+ip+'\n' for ip in peer_ips.split(','))
  for attempt in range(100):
   try:
    with socket.socket(socket.AF_UNIX) as control:
     control.settimeout(3);control.connect('/run/vault443/amneziawg/'+name+'.sock');control.sendall(('set=1\n'+text+'\n').encode());assert control.recv(4096)==b'errno=0\n\n'
    break
   except (FileNotFoundError,ConnectionRefusedError):time.sleep(.1)
  else:raise RuntimeError('AWG server did not create its private control channel')
 run('ip','address','replace',f'198.19.{subnet-36}.1/24','dev',name)
 run('ip','-6','address','replace',f'2001:db8:{subnet}::1/64','dev',name,'nodad')
 run('ip','link','set',name,'mtu','1280','up')
 run('ip','address','replace',f'198.19.{subnet-36}.10/32','dev','lo')
 run('ip','-6','address','replace',f'2001:db8:{subnet}::10/128','dev','lo')
 private_client=awg_client if kind=='amneziawg' else client
 body=f'[Interface]\nPrivateKey = {private_client}\nAddress = 198.19.{subnet-36}.2/32,2001:db8:{subnet}::2/128\nMTU = 1280\nDNS = 198.19.{subnet-36}.1,2001:db8:{subnet}::1,{"awg" if kind=="amneziawg" else "wg"}.e2e.test\n'
 if kind=='amneziawg':body+=''.join(key+' = '+value+'\n' for key,value in params.items())
 body+=f'[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\nEndpoint = 192.0.2.1:{port}\nAllowedIPs = 198.19.{subnet-36}.0/24,2001:db8:{subnet}::/64\n'
 filename='amneziawg' if kind=='amneziawg' else 'wireguard' if subnet==80 else 'wireguard-peer2'
 (clients/(filename+'.conf')).write_text(body)
 if subnet==80:
  full=body.replace('198.19.44.0/24,2001:db8:80::/64','0.0.0.0/0,::/0').replace('198.19.44.1,2001:db8:80::1,wg.e2e.test','198.19.44.1')
  (clients/'wireguard-full.conf').write_text(full)
for family,source,destinations in [('-4','198.19.46.0/24',['198.19.44.2/32','198.19.46.2/32']),('-6','2001:db8:82::/64',['2001:db8:80::2/128','2001:db8:82::2/128'])]:
 for destination in destinations:run('ip',family,'route','replace',destination,'dev','v443srvwg3','table','44482')
 run('ip',family,'rule','add','priority','10482','from',source,'table','44482')
multi=(clients/'wireguard.conf').read_text().replace('198.19.44.2/32,2001:db8:80::2/128','198.19.44.2/32,2001:db8:80::2/128,198.19.46.2/32,2001:db8:82::2/128')
multi+=f'[Peer]\nPublicKey = {publics[82]}\nPresharedKey = {psk}\nEndpoint = 192.0.2.1:51822\nAllowedIPs = 198.19.46.0/24,2001:db8:82::/64\n'
(clients/'wireguard-multi.conf').write_text(multi)
for path in clients.glob('*.conf'):
 files=json.dumps([{'name':'Vault443 Fixture '+path.stem,'content':path.read_text()}])
 (clients/(path.stem+'-import.json')).write_text(json.dumps([files]))
PY
cat >/fixture/wireguard/web.py <<'PY'
import http.server,json,socket,threading
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=json.dumps({'marker':'work-e2e-ok','peer':self.client_address[0],'destination':self.server.server_address[0]}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
class IPv6Server(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
for subnet in [80,81,82]:
 for address,server in [(f'198.19.{subnet-36}.10',http.server.ThreadingHTTPServer),(f'2001:db8:{subnet}::10',IPv6Server)]:
  threading.Thread(target=server((address,18080),Handler).serve_forever,daemon=True).start()
threading.Event().wait()
PY
systemd-run --unit=vault443-fixture-wg-web --collect --property=Restart=on-failure /usr/bin/python3 /fixture/wireguard/web.py
systemd-run --unit=vault443-fixture-wg-dns --collect --property=Restart=on-failure /usr/sbin/dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces --listen-address=198.19.44.1,198.19.45.1,198.19.46.1,2001:db8:80::1,2001:db8:81::1,2001:db8:82::1 --address=/peer2.wg.e2e.test/198.19.46.10 --address=/peer2.wg.e2e.test/2001:db8:82::10 --address=/wg.e2e.test/198.19.44.10 --address=/wg.e2e.test/2001:db8:80::10 --address=/awg.e2e.test/198.19.45.10 --address=/awg.e2e.test/2001:db8:81::10 --address=/#/93.184.215.14
chown -R vaultfixture:vaultfixture /home/vaultfixture/wireguard
chmod 0700 /home/vaultfixture/wireguard
chmod 0600 /home/vaultfixture/wireguard/*
echo 'Temporary WireGuard/AWG fixtures ready; credentials remain in the isolated guest'
