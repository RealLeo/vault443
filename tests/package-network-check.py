#!/usr/bin/env python3
"""Validate package upgrades over the isolated VLESS test fixture."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
assert Path('/.dockerenv').exists() and os.getenv('VAULT443_E2E_ISOLATED') == '1'
mode = sys.argv[1]

def physical():
    s = socket.socket()
    s.settimeout(.8)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'e2euplink\0')
    try:
        s.connect(('93.184.215.14', 443))
        return True
    except OSError:
        return False
    finally:
        s.close()

if mode == 'monitor':
    # The caller removes the stop marker only after a verified reconnect.
    stop = Path('/tmp/guard-monitor-stop')
    Path('/tmp/guard-monitor-ready').touch()
    samples = 0
    while not stop.exists():
        assert not physical(), 'Direct physical traffic escaped during package upgrade'
        samples += 1
        time.sleep(.03)
    assert samples > 0
    print('PASS: continuous physical bypass monitor: ' + str(samples) + ' blocked attempts')
    sys.exit(0)
elif mode == 'blocked':
    assert not physical(), 'Physical direct traffic escaped the guard'
    print('PASS: direct physical IPv4 is blocked')
else:
    base = 'vault443'
    interface = 'vault4430'
    last_error = ''
    for _ in range(150):
        route = subprocess.run(['ip', '-j', 'route', 'get', '93.184.215.14'], capture_output=True, text=True)
        routes = json.loads(route.stdout) if route.returncode == 0 else []
        if routes and routes[0].get('dev') == interface:
            r = subprocess.run(['curl', '--noproxy', '*', '--fail', '--silent', '--show-error',
                                '--max-time', '2', '--resolve',
                                'web.e2e.example.com:443:93.184.215.14',
                                'https://web.e2e.example.com/'], capture_output=True, text=True)
            if r.returncode == 0:
                break
            last_error = r.stderr
        time.sleep(.2)
    else:
        if os.getenv('VAULT443_REAL_SYSTEMD') == '1':
            subprocess.run(['journalctl','--no-pager','-u',base+'.service','-n','40'])
        else:
            print(Path('/tmp/' + base + '-test-daemon.log').read_text())
        raise AssertionError('Connection did not recover through ' + interface + ': ' + last_error)
    assert not physical(), 'Direct physical bypass remained after reconnect'
    print('PASS: ' + base + ' connected through real local VLESS; physical bypass blocked')
