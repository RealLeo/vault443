#!/usr/bin/env python3
"""Extend only the disposable fixture. Every credential below is synthetic."""
import base64
import json
from pathlib import Path

p = Path('/fixture/server.json')
config = json.loads(p.read_text())
profiles = []
for i, transport in enumerate(['tcp', 'ws', 'grpc', 'xhttp']):
    port = 8450 + i
    stream = dict(network=transport, security='tls', tlsSettings=dict(certificates=[dict(certificateFile='/fixture/server.crt', keyFile='/fixture/server.key')]))
    extra = ''
    if transport == 'ws':
        stream['wsSettings'] = dict(path='/synthetic')
        extra = '&path=%2Fsynthetic'
    if transport == 'grpc':
        stream['grpcSettings'] = dict(serviceName='synthetic')
        extra = '&serviceName=synthetic'
    if transport == 'xhttp':
        stream['xhttpSettings'] = dict(path='/synthetic', mode='auto')
        extra = '&path=%2Fsynthetic'
    config['inbounds'].append(dict(listen='192.0.2.1', port=port, protocol='trojan', settings=dict(clients=[dict(password='synthetic-password')]), streamSettings=stream))
    profiles.append('trojan://synthetic-password@192.0.2.1:'+str(port)+'?security=tls&type='+transport+'&sni=vpn.e2e.invalid'+extra+'#Trojan-'+transport)

for i, method in enumerate(['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305']):
    port = 8500 + i
    password = 'synthetic-password'
    settings = dict(network='tcp,udp', method=method)
    if method.startswith('2022-'):
        size = 16 if '128' in method else 32
        password = base64.b64encode(bytes(range(size))).decode()
    settings['password'] = password
    if method.startswith('2022-') and 'aes' in method:
        client = base64.b64encode(bytes(reversed(range(size)))).decode()
        settings['clients'] = [dict(password=client, email='synthetic@test.invalid')]
        settings['users'] = settings['clients']
        password += ':' + client
    config['inbounds'].append(dict(listen='192.0.2.1', port=port, protocol='shadowsocks', settings=settings))
    from urllib.parse import quote
    profiles.append('ss://'+method+':'+quote(password, safe='')+'@192.0.2.1:'+str(port)+'#'+method)
p.write_text(json.dumps(config))
Path('/fixture/proxy-links.txt').write_text('\n'.join(profiles))

exit_config = dict(log=dict(loglevel='warning'), inbounds=[dict(listen='93.184.215.14', port=8550, protocol='shadowsocks', settings=dict(network='tcp,udp', method='aes-256-gcm', password='synthetic-password'))], outbounds=[dict(protocol='freedom')])
Path('/fixture/outline-exit.json').write_text(json.dumps(exit_config))
