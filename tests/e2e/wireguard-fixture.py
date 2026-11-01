#!/usr/bin/env python3
"""Synthetic WG/AWG servers in the existing, network-none E2E namespace."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import time

assert Path('/.dockerenv').exists()
assert os.environ.get('VAULT443_E2E_ISOLATED') == '1'
assert os.environ.get('VAULT443_WIREGUARD_E2E') == '1'
assert Path('/fixture/work/client-1.ovpn').exists()
root = Path('/fixture/wireguard')
root.mkdir(mode=0o700)
os.umask(0o077)


def run(*args, input=None):
    return subprocess.check_output(args, input=input, stderr=subprocess.PIPE)


def server(*args):
    return run('ip', 'netns', 'exec', 'fixture', *args)


def keypair():
    private = run('wg', 'genkey').strip().decode()
    public = run('wg', 'pubkey', input=(private + '\n').encode()).strip().decode()
    return private, public


def uapi(name, configuration):
    path = '/run/vault443/amneziawg/' + name + '.sock'
    for attempt in range(100):
        try:
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(2)
            sock.connect(path)
            with sock:
                sock.sendall(('set=1\n' + configuration + '\n').encode())
                reply = sock.recv(4096)
                assert reply == b'errno=0\n\n', 'AWG server rejected synthetic settings'
            return
        except (FileNotFoundError, ConnectionRefusedError):
            sock.close()
            time.sleep(.05)
    raise RuntimeError('AWG server UAPI not available')


def hexkey(value):
    return base64.b64decode(value).hex()


client_private, client_public = keypair()
client2_private, client2_public = keypair()
psk = run('wg', 'genpsk').strip().decode()
awg_parameters = {
    'Jc': '2', 'Jmin': '40', 'Jmax': '64',
    'S1': '16', 'S2': '17', 'S3': '18', 'S4': '19',
    'H1': '101-110', 'H2': '201-210', 'H3': '301-310', 'H4': '401-410',
    'I1': '<b 0xaabb><r 8>',
    'HeaderProtectionKey': keypair()[0], 'ContentPaddingAddition': '0-8',
    'RandomTrailers': 'true', 'DisableCookies': 'false',
}
awg_uapi_names = {'HeaderProtectionKey': 'header_protection_key',
                  'ContentPaddingAddition': 'content_padding_addition',
                  'RandomTrailers': 'random_trailers', 'DisableCookies': 'disable_cookies'}
public_keys = {}
for number, kind, port, octet in [(1, 'wireguard', 51820, 80), (2, 'amneziawg', 51821, 81), (3, 'wireguard', 51822, 82), (4, 'amneziawg', 51823, 83), (5, 'amneziawg', 51824, 84)]:
    private, public = keypair()
    public_keys[number] = public
    name = 'wgserver' + str(number)
    peer_public = client2_public if kind == 'amneziawg' else client_public
    current_parameters = dict(awg_parameters)
    if number == 4:
        current_parameters = {'Jc': '2', 'Jmin': '40', 'Jmax': '64', 'S1': '1', 'S2': '2', 'H1': '101', 'H2': '201', 'H3': '301', 'H4': '401'}
    elif number == 5:
        current_parameters = {k: v for k, v in awg_parameters.items() if k in ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1')}
    peer_ips = f'10.{octet}.0.2/32, 2001:db8:{octet}::2/128'
    if number == 3:
        peer_ips += ', 10.80.0.2/32, 2001:db8:80::2/128'
    if kind == 'wireguard':
        server('ip', 'link', 'add', name, 'type', 'wireguard')
        config = root / f'server-{number}.conf'
        config.write_text(f'[Interface]\nPrivateKey = {private}\nListenPort = {port}\n'
                          f'[Peer]\nPublicKey = {peer_public}\nPresharedKey = {psk}\nAllowedIPs = {peer_ips}\n')
        server('wg', 'setconf', name, str(config))
    else:
        with open(f'/results/awg-server-{number}.log', 'wb') as output:
            proc = subprocess.Popen(['ip', 'netns', 'exec', 'fixture', '/usr/lib/vault443/amneziawg-go', '-f', name],
                                    stdout=output, stderr=subprocess.STDOUT)
        (root / f'awg-server-{number}.pid').write_text(str(proc.pid))
        params = ''
        for key, value in current_parameters.items():
            if key == 'HeaderProtectionKey':
                value = hexkey(value)
            if value in ('true', 'false'):
                value = '1' if value == 'true' else '0'
            params += awg_uapi_names.get(key, key.lower()) + '=' + value + '\n'
        uapi(name, f'private_key={hexkey(private)}\nlisten_port={port}\n' + params
             + f'public_key={hexkey(peer_public)}\npreshared_key={hexkey(psk)}\n'
             + ''.join('allowed_ip=' + ip.strip() + '\n' for ip in peer_ips.split(',')))
    server('ip', 'addr', 'add', f'10.{octet}.0.1/24', 'dev', name)
    server('ip', '-6', 'addr', 'add', f'2001:db8:{octet}::1/64', 'dev', name, 'nodad')
    server('ip', 'link', 'set', name, 'mtu', '1280', 'up')
    private_client = client2_private if kind == 'amneziawg' else client_private
    allowed = f'10.{octet}.0.0/24, 2001:db8:{octet}::/64'
    allowed += ', 192.168.0.0/16, 2001:db8:100::/64' if number == 1 else ', 10.42.0.0/24'
    params = ''.join(key + ' = ' + value + '\n' for key, value in current_parameters.items()) if kind == 'amneziawg' else ''
    config = f'[Interface]\nPrivateKey = {private_client}\nAddress = 10.{octet}.0.2/32, 2001:db8:{octet}::2/128\n'
    config += f'MTU = 1280\nDNS = 10.{octet}.0.1, wg{number}.e2e.test\n' + params
    config += f'[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\nEndpoint = 192.0.2.1:{port}\nAllowedIPs = {allowed}\nPersistentKeepalive = 1\n'
    (root / f'client-{number}.conf').write_text(config)

# Multi-peer replies to the first client's source must go back to the peer
# serving 10.42/24, without affecting unrelated OpenVPN/AWG clients.
server('ip', 'route', 'add', '10.80.0.2/32', 'dev', 'wgserver3', 'table', '82')
server('ip', 'rule', 'add', 'from', '10.42.0.15/32', 'lookup', '82')
server('ip', 'rule', 'add', 'from', '10.82.0.0/24', 'lookup', '82')
multi = (root / 'client-1.conf').read_text()
multi += f'[Peer]\nPublicKey = {public_keys[3]}\nPresharedKey = {psk}\nEndpoint = 192.0.2.1:51822\nAllowedIPs = 10.42.0.0/24, 10.82.0.0/24\nPersistentKeepalive = 1\n'
(root / 'multi.conf').write_text(multi)

# The existing work fixture provides HTTP at the protected addresses. Start
# additional DNS listeners for both protocol implementations with distinct zones.
source = Path('/fixture/work/servers.py').read_text()
begin = source.index('def dns(')
end = source.index('for bind,answer', begin)
dns = 'import socket,struct,threading,time\n' + source[begin:end]
dns += "\nfor bind,answer in [('10.80.0.1','192.168.100.15'),('10.81.0.1','10.42.0.15'),('10.82.0.1','10.42.0.15'),('10.83.0.1','10.42.0.15'),('10.84.0.1','10.42.0.15')]:\n    threading.Thread(target=dns,args=(bind,answer),daemon=True).start()\nthreading.Event().wait()\n"
(root / 'dns.py').write_text(dns)
with open('/results/wireguard-dns.log', 'wb') as output:
    subprocess.Popen(['ip', 'netns', 'exec', 'fixture', 'python3', str(root / 'dns.py')], stdout=output, stderr=subprocess.STDOUT)
print('Synthetic WireGuard and AmneziaWG servers ready; keys remain inside the isolated fixture')
