#!/usr/bin/env python3
"""Run only inside the isolated Linux fixture against fixed Windows QA listeners."""
import argparse
import datetime
import json
from pathlib import Path
import secrets
import socket
import stat
import time


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def guard():
    marker = Path('/etc/vault443-fixture-guest')
    info = marker.stat()
    model = Path('/sys/class/dmi/id/product_name').read_text().strip()
    if (socket.gethostname() != 'vault443-fixture' or 'VirtualBox' not in model
            or info.st_uid != 0 or not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o022):
        raise SystemExit('The protected isolated VirtualBox fixture is required')


def connection(source, destination, udp=False):
    family = socket.AF_INET6 if ':' in source else socket.AF_INET
    peer = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    try:
        peer.settimeout(2)
        peer.bind((source, 0))
        peer.connect((destination, 18083 if udp else 18082))
        return peer
    except BaseException:
        peer.close()
        raise


def exchange(peer):
    payload = b'vault443-inbound-' + secrets.token_hex(12).encode('ascii')
    peer.sendall(payload)
    answer = bytearray()
    while len(answer) < len(payload):
        part = peer.recv(len(payload) - len(answer))
        if not part:
            break
        answer.extend(part)
    return bytes(answer) == payload


def main():
    guard()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=['new', 'hold'], default='new')
    parser.add_argument('--offlink', choices=['allowed', 'blocked'], default='blocked')
    parser.add_argument('--seconds', type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 120:
        parser.error('--seconds must be 1..120')
    pairs = [('192.0.2.1', '192.0.2.2', False),
             ('2001:db8:44::1', '2001:db8:44::2', False),
             ('93.184.215.14', '192.0.2.2', True),
             ('2001:db8:66::14', '2001:db8:44::2', True)]
    if args.kind == 'new':
        checks = []
        for source, destination, offlink in pairs:
            for udp in [False, True]:
                row = dict(utc=utc(), source=source, destination=destination,
                           udp=udp, offlink=offlink, echoed=False, error=None)
                try:
                    with connection(source, destination, udp) as peer:
                        row['echoed'] = exchange(peer)
                except OSError as error:
                    row['error'] = type(error).__name__
                expected = not offlink or args.offlink == 'allowed'
                row['passed'] = row['echoed'] == expected
                checks.append(row)
        print(json.dumps(dict(utc=utc(), kind='new', expectedOfflink=args.offlink,
                              passed=all(row['passed'] for row in checks), checks=checks)), flush=True)
        return 0 if all(row['passed'] for row in checks) else 1
    # Open before arming. The controller records the exact arm/disconnect UTC
    # separately; each observation can be correlated with the fixture pcap.
    peers = []
    try:
        for source, destination, offlink in pairs:
            if offlink:
                peers.append((source, connection(source, destination)))
        print(json.dumps(dict(utc=utc(), kind='hold-ready', sources=[s for s, _ in peers])), flush=True)
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            for source, peer in peers:
                row = dict(utc=utc(), kind='hold', source=source, echoed=False, error=None)
                try:
                    row['echoed'] = exchange(peer)
                except OSError as error:
                    row['error'] = type(error).__name__
                print(json.dumps(row), flush=True)
            time.sleep(1)
    finally:
        for _, peer in peers:
            peer.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
