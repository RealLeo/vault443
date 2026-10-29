#!/usr/bin/env python3
"""Actual work traffic and fail-closed checks in the package PID1 fixture."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

assert Path('/.dockerenv').exists() and os.getenv('VAULT443_E2E_ISOLATED') == '1'
assert os.getenv('VAULT443_PACKAGE_TEST') == '1'
targets = [('192.168.100.15', '10.70.'), ('10.42.0.15', '10.71.')]

def bypass(address):
    with socket.socket() as s:
        s.settimeout(.2)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'e2euplink\0')
        try:
            s.connect((address,8081))
            return True
        except OSError:
            return False

if sys.argv[1] == 'monitor':
    Path('/tmp/work-monitor-ready').touch()
    samples=0
    while not Path('/tmp/work-monitor-stop').exists():
        for address,_ in targets:
            assert not bypass(address), 'Work traffic escaped during daemon crash'
            samples+=1
        time.sleep(.03)
    print('PASS: work-route crash monitor: %d blocked physical attempts' % samples)
else:
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for address,prefix in targets:
        for attempt in range(120):
            try:
                with opener.open('http://%s:8081/' % address, timeout=1) as response:
                    data=json.load(response)
                assert data['marker']=='work-vpn-ok' and data['peer'].startswith(prefix)
                break
            except (OSError,AssertionError):
                time.sleep(.2)
        else:
            subprocess.run(['journalctl','--no-pager','-u','vault443.service','-n','40'])
            raise AssertionError('Work connection did not recover through its own tunnel')
        assert not bypass(address), 'Work route allowed physical bypass'
    print('PASS: two work destinations use independent OpenVPN tunnels, including Docker overlap')
