#!/bin/bash
set -euo pipefail
# Sourced only after entrypoint.sh has asserted a network-none disposable
# container. All keys below are fresh throwaway fixture material.
test -f /.dockerenv
test "${VAULT443_E2E_ISOLATED:-}" = 1
test "${VAULT443_WORKVPN_E2E:-}" = 1
command -v openvpn >/dev/null
mkdir -p /fixture/work
chmod 0700 /fixture/work
openssl req -newkey rsa:2048 -nodes -subj /CN=Vault443-Work-Test-Client \
  -keyout /fixture/work/client.key -out /fixture/work/client.csr >>/results/cert.log 2>&1
cat >/fixture/work/client.ext <<'EXT'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature
basicConstraints=CA:FALSE
EXT
openssl x509 -req -in /fixture/work/client.csr -CA /fixture/ca.crt -CAkey /fixture/ca.key \
  -CAcreateserial -out /fixture/work/client.crt -days 2 -sha256 \
  -extfile /fixture/work/client.ext >>/results/cert.log 2>&1
openvpn --genkey secret /fixture/work/tls-auth.key
chmod 0600 /fixture/work/*
for index in 1 2 3; do
  port=$((1193 + index))
  octet=$((69 + index))
  cat >"/fixture/work/server-$index.conf" <<CFG
port $port
proto udp
dev wserver$index
dev-type tun
topology subnet
server 10.$octet.0.0 255.255.255.0
ca /fixture/ca.crt
cert /fixture/server.crt
key /fixture/server.key
dh none
tls-auth /fixture/work/tls-auth.key 0
cipher AES-128-CBC
data-ciphers AES-128-GCM:AES-128-CBC
auth SHA1
comp-lzo no
keepalive 1 5
duplicate-cn
persist-key
persist-tun
verb 3
push "dhcp-option DNS 10.$octet.0.1"
push "dhcp-option DOMAIN work$index.e2e.test"
CFG
  if [ "$index" = 1 ]; then
    printf 'server-ipv6 2001:db8:70::/64\npush "route-ipv6 2001:db8:100::/64"\npush "route 192.168.0.0 255.255.0.0"\n' >>"/fixture/work/server-$index.conf"
  elif [ "$index" = 2 ]; then
    printf 'push "route 10.42.0.0 255.255.255.0"\n' >>"/fixture/work/server-$index.conf"
  else
    printf 'push "redirect-gateway def1"\n' >>"/fixture/work/server-$index.conf"
  fi
  ip netns exec fixture /usr/sbin/openvpn --config "/fixture/work/server-$index.conf" \
    >"/results/work-server-$index.log" 2>&1 &
  printf '%s\n' "$!" >"/fixture/work/server-$index.pid"
  cat >"/fixture/work/client-$index.ovpn" <<CFG
client
dev tun
dev-type tun
remote 192.0.2.1 $port udp
nobind
persist-tun
cipher AES-128-CBC
data-ciphers AES-128-GCM:AES-128-CBC
auth SHA1
remote-cert-tls server
verb 2
ping 1
ping-restart 5
hand-window 10
server-poll-timeout 5
reneg-sec 0
comp-lzo no
key-direction 1
CFG
  for kind in ca cert key tls-auth; do
    case "$kind" in
      ca) source=/fixture/ca.crt;;
      cert) source=/fixture/work/client.crt;;
      key) source=/fixture/work/client.key;;
      tls-auth) source=/fixture/work/tls-auth.key;;
    esac
    printf '<%s>\n' "$kind" >>"/fixture/work/client-$index.ovpn"
    cat "$source" >>"/fixture/work/client-$index.ovpn"
    printf '</%s>\n' "$kind" >>"/fixture/work/client-$index.ovpn"
  done
  chmod 0600 "/fixture/work/client-$index.ovpn"
done
# Reproduce the user's address collision without touching any host Docker
# network. No endpoint exists on this bridge, so incorrect routing fails.
ip link add wdock type bridge
ip addr add 192.168.96.1/20 dev wdock
ip link set wdock up
# A disposable namespace reproduces Docker bridge forwarding and source NAT.
# Its explicit corporate host route also makes overlapping container-local
# addressing reach the gateway, rather than ARPing the destination on eth0.
ip netns add work-docker
ip link add wclient type veth peer name eth0 netns work-docker
ip link set wclient master wdock
ip link set wclient up
ip netns exec work-docker ip link set lo up
ip netns exec work-docker ip addr add 192.168.96.2/20 dev eth0
ip netns exec work-docker ip link set eth0 up
ip netns exec work-docker ip route add default via 192.168.96.1
ip netns exec work-docker ip route add 192.168.100.15/32 via 192.168.96.1
# The Docker runner enables forwarding only in this disposable namespace.
# Keep default reverse-path filtering to exercise production routing correctly.
if [ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]; then
  echo 'Work forwarding fixture requires container --sysctl net.ipv4.ip_forward=1' >&2
  exit 1
fi
nft -f - <<'NFT'
table ip work_fixture_docker {
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 192.168.96.0/20 oifname != "wdock" masquerade
 }
}
NFT
if [ "${VAULT443_REAL_SYSTEMD:-}" = 1 ]; then
  nmcli device set wdock managed no
  nmcli device set wclient managed no
fi
# A real physical IPv6 route makes a failed closed-route assertion meaningful:
# absent the work guard, this destination is directly reachable.
ip -6 addr add 2001:db8:2::2/64 dev e2euplink nodad
ip netns exec fixture ip -6 addr add 2001:db8:2::1/64 dev e2eserver nodad
ip -6 route add 2001:db8:100::/64 via 2001:db8:2::1 dev e2euplink
ip netns exec fixture ip -6 addr add 2001:db8:100::15/128 dev lo nodad
ip netns exec fixture ip addr add 192.168.100.15/32 dev lo
ip netns exec fixture ip addr add 10.42.0.15/32 dev lo
cat >/fixture/work/servers.py <<'PY'
import http.server, json, socket, struct, threading, time
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'marker':'work-vpn-ok','peer':self.client_address[0], 'server':self.server.server_address[0]}).encode()
        self.send_response(200); self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass
class IPv6HTTPServer(http.server.ThreadingHTTPServer):
    address_family=socket.AF_INET6
threading.Thread(target=IPv6HTTPServer(('2001:db8:100::15',8081),Handler).serve_forever,daemon=True).start()
for address in ['192.168.100.15','10.42.0.15']:
    threading.Thread(target=http.server.ThreadingHTTPServer((address,8081),Handler).serve_forever,daemon=True).start()
def dns(bind, answer):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    for _ in range(200):
        try: sock.bind((bind,53)); break
        except OSError: time.sleep(.1)
    else: raise RuntimeError('OpenVPN DNS fixture failed to bind')
    while True:
        data,peer=sock.recvfrom(4096)
        if len(data)<12: continue
        end=12
        try:
            while data[end]: end+=1+data[end]
            end+=5
            qtype=struct.unpack('!H',data[end-4:end-2])[0]
            question=data[12:end]
            records=b''
            if qtype==1: records=b'\xc0\x0c'+struct.pack('!HHIH',1,1,15,4)+socket.inet_aton(answer)
            response=data[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(records)),0,0)+question+records
            sock.sendto(response,peer)
        except (IndexError,struct.error): continue
for bind,answer in [('10.70.0.1','192.168.100.15'),('10.71.0.1','10.42.0.15'),('10.72.0.1','192.168.100.15')]:
    threading.Thread(target=dns,args=(bind,answer),daemon=True).start()
threading.Event().wait()
PY
ip netns exec fixture python3 /fixture/work/servers.py >/results/work-web-dns.log 2>&1 &
for attempt in $(seq 1 100); do
  if ip netns exec fixture ip link show wserver1 >/dev/null 2>&1 && \
     ip netns exec fixture ip link show wserver2 >/dev/null 2>&1 && \
     ip netns exec fixture ip link show wserver3 >/dev/null 2>&1; then break; fi
  sleep .1
done
ip netns exec fixture ip link show wserver1 >/dev/null
ip netns exec fixture ip link show wserver2 >/dev/null

ip netns exec fixture ip link show wserver3 >/dev/null
