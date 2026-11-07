#!/usr/bin/env python3
"""Offline, payload-redacting analysis of the fixed isolated inbound WFP test.

Accepts classic Ethernet pcap (microsecond or nanosecond timestamps), not pcapng.
Only the fixture's Windows addresses, four peers and QA listener ports count.
No packet contents or random echo tokens are included in the JSON output.
"""
import argparse
from collections import Counter
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import struct


WINDOWS = {4: '192.0.2.2', 6: '2001:db8:44::2'}
LAN = {4: '192.0.2.1', 6: '2001:db8:44::1'}
OFFLINK = {4: '93.184.215.14', 6: '2001:db8:66::14'}
PORTS = {6: 18082, 17: 18083}
MARKER = b'vault443-inbound-'
RECORD_BYTES = len(MARKER) + 24


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def epoch_ns(value):
    value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise ValueError('UTC/time-zone-qualified timestamps are required')
    delta = value.astimezone(dt.timezone.utc) - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def utc(ns):
    return dt.datetime.fromtimestamp(ns / 1e9, dt.timezone.utc).isoformat(timespec='microseconds')


def packets(path):
    with path.open('rb') as source:
        header = source.read(24)
        magics = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
                  b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}
        if len(header) != 24 or header[:4] not in magics:
            raise ValueError('A complete classic pcap header is required')
        endian, scale = magics[header[:4]]
        major, minor, _, _, snaplen, link = struct.unpack(endian + 'HHIIII', header[4:])
        if (major, minor) != (2, 4) or link != 1 or not 0 < snaplen <= 16 << 20:
            raise ValueError('Only bounded Ethernet pcap 2.4 is supported')
        while record := source.read(16):
            if len(record) != 16:
                raise ValueError('Truncated pcap record header')
            seconds, fraction, included, original = struct.unpack(endian + 'IIII', record)
            if included > snaplen or included > original:
                raise ValueError('Invalid pcap packet length')
            frame = source.read(included)
            if len(frame) != included or included != original:
                raise ValueError('Truncated capture cannot prove absence of leakage')
            yield seconds * 1_000_000_000 + fraction * scale, frame


def decode(frame):
    if len(frame) < 14:
        raise ValueError('Short Ethernet frame')
    offset, kind = 14, struct.unpack_from('!H', frame, 12)[0]
    while kind in (0x8100, 0x88a8):
        if len(frame) < offset + 4:
            raise ValueError('Short VLAN header')
        kind = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    ip = frame[offset:]
    if kind == 0x0800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            raise ValueError('Invalid IPv4 header')
        family, pos, end, proto = 4, (ip[0] & 15) * 4, struct.unpack_from('!H', ip, 2)[0], ip[9]
        src, dst = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
        fragmented = struct.unpack_from('!H', ip, 6)[0] & 0x3fff
    elif kind == 0x86dd:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            raise ValueError('Invalid IPv6 header')
        family, pos, end, proto, fragmented = 6, 40, 40 + struct.unpack_from('!H', ip, 4)[0], ip[6], False
        src, dst = str(ipaddress.ip_address(ip[8:24])), str(ipaddress.ip_address(ip[24:40]))
        while proto in (0, 43, 60, 44, 51):
            if len(ip) < pos + 8:
                raise ValueError('Short IPv6 extension header')
            following = ip[pos]
            if proto == 44:
                fragmented = struct.unpack_from('!H', ip, pos + 2)[0] & 0xfff9
                length = 8
            elif proto == 51:
                length = (ip[pos + 1] + 2) * 4
            else:
                length = (ip[pos + 1] + 1) * 8
            pos, proto = pos + length, following
    else:
        return None
    if src not in (WINDOWS[family], LAN[family], OFFLINK[family]) or dst not in (WINDOWS[family], LAN[family], OFFLINK[family]):
        return None
    if fragmented:
        raise ValueError('Fragmented fixture traffic needs a separate reassembly analysis')
    if not pos <= end <= len(ip):
        raise ValueError('Truncated IP packet')
    if proto not in PORTS:
        return None
    transport = ip[pos:end]
    if len(transport) < (20 if proto == 6 else 8):
        raise ValueError('Short fixture transport header')
    sport, dport = struct.unpack_from('!HH', transport)
    reply = src == WINDOWS[family] and sport == PORTS[proto] and dst in (LAN[family], OFFLINK[family])
    request = dst == WINDOWS[family] and dport == PORTS[proto] and src in (LAN[family], OFFLINK[family])
    if not reply and not request:
        return None
    if proto == 6:
        size, seq, flags = (transport[12] >> 4) * 4, struct.unpack_from('!I', transport, 4)[0], transport[13]
        if not 20 <= size <= len(transport):
            raise ValueError('Invalid TCP data offset')
        payload = transport[size:]
    else:
        length = struct.unpack_from('!H', transport, 4)[0]
        if not 8 <= length <= len(transport):
            raise ValueError('Invalid UDP length')
        payload, seq, flags = transport[8:length], None, 0
    peer, peer_port = (dst, dport) if reply else (src, sport)
    return dict(family=family, protocol='TCP' if proto == 6 else 'UDP', reply=reply,
                peer=peer, peerPort=peer_port, offlink=peer == OFFLINK[family],
                payload=payload, seq=seq, syn=bool(flags & 2), ack=bool(flags & 16))


def echo_records(segments):
    # The bounded fixture sends fixed-size records. Byte positions also exclude
    # retransmissions and permit TCP packet coalescing without printing tokens.
    octets = {}
    for seq, data, when in segments:
        for offset, value in enumerate(data):
            position = seq + offset
            if position in octets and octets[position][0] != value:
                raise ValueError('Conflicting TCP retransmission')
            octets.setdefault(position, (value, when))
    if not octets:
        return []
    positions = sorted(octets)
    if positions[-1] - positions[0] + 1 != len(positions):
        raise ValueError('A fixture TCP stream has a capture gap')
    data = bytes(octets[position][0] for position in positions)
    records = []
    for index in range(0, len(data) - RECORD_BYTES + 1, RECORD_BYTES):
        record = data[index:index + RECORD_BYTES]
        if not record.startswith(MARKER) or any(value not in b'0123456789abcdef' for value in record[len(MARKER):]):
            raise ValueError('Unexpected data on the fixed fixture listener')
        records.append((record, max(octets[position][1] for position in positions[index:index + RECORD_BYTES])))
    return records


def analyze(args):
    arm_report = load(args.arm_report)
    checks = [row for row in arm_report.get('checks', []) if row.get('passed') and row.get('observation', {}).get('guardArmed') and row.get('observation', {}).get('state') == 'connected']
    if not arm_report.get('passed') or len(checks) != 1:
        raise ValueError('One successful connected+guardArmed check is required')
    arm = epoch_ns(checks[0]['utc'])
    counts, windows, flows = {}, {}, {}
    total = 0
    first = last = None
    for when, frame in packets(args.pcap):
        first = when if first is None else min(first, when)
        last = when if last is None else max(last, when)
        total += 1
        packet = decode(frame)
        if not packet:
            continue
        key = (packet['family'], packet['protocol'], packet['offlink'])
        label = f"IPv{key[0]}-{key[1]}-{'offlink' if key[2] else 'LAN'}"
        row = counts.setdefault(label, dict(requestPacketsAfterArm=0, replyPayloadPacketsAfterArm=0, replyPayloadBytesAfterArm=0))
        if when > arm:
            if not packet['reply']:
                row['requestPacketsAfterArm'] += 1
            if packet['reply'] and packet['payload']:
                row['replyPayloadPacketsAfterArm'] += 1
                row['replyPayloadBytesAfterArm'] += len(packet['payload'])
                times = windows.setdefault(label, [])
                times.append(when)
        if packet['protocol'] == 'TCP':
            key = (packet['family'], packet['peer'], packet['peerPort'])
            flow = flows.setdefault(key, dict(syn=None, request=[], reply=[], afterPackets=0, afterBytes=0))
            if packet['syn'] and not packet['ack'] and not packet['reply']:
                flow['syn'] = when if flow['syn'] is None else min(flow['syn'], when)
            if packet['payload']:
                flow['reply' if packet['reply'] else 'request'].append((packet['seq'], packet['payload'], when))
                if packet['reply'] and when > arm:
                    flow['afterPackets'] += 1
                    flow['afterBytes'] += len(packet['payload'])
    if first is None or not first < arm < last:
        raise ValueError('Capture must span the connected/armed observation')
    for label, row in counts.items():
        if label in windows:
            row.update(firstReplyPayloadAfterArmUtc=utc(min(windows[label])), lastReplyPayloadAfterArmUtc=utc(max(windows[label])) )
    preexisting = []
    for (family, peer, port), flow in sorted(flows.items()):
        if peer != OFFLINK[family] or flow['syn'] is None or flow['syn'] >= arm:
            continue
        requests = {record for record, _ in echo_records(flow['request'])}
        echoed = [when for record, when in echo_records(flow['reply']) if when > arm and record in requests]
        preexisting.append(dict(family=f'IPv{family}', peer=peer, clientPort=port,
                                synUtc=utc(flow['syn']), replyPayloadPacketsAfterArm=flow['afterPackets'],
                                replyPayloadBytesAfterArm=flow['afterBytes'], matchedEchoRecordsAfterArm=len(echoed)))
    application = {}
    if args.hold:
        rows = [json.loads(line) for line in args.hold.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
        for family, peer in OFFLINK.items():
            after = [row for row in rows if row.get('kind') == 'hold' and row.get('source') == peer and epoch_ns(row['utc']) > arm]
            application[f'IPv{family}'] = dict(observationsAfterArm=len(after), echoedAfterArm=sum(row.get('echoed') is True for row in after), failuresAfterArm=sum(row.get('echoed') is not True for row in after))
    baseline_ok = False
    if args.baseline:
        baseline = load(args.baseline)
        baseline_ok = baseline.get('passed') is True and len(baseline.get('checks', [])) == 8 and all(row.get('echoed') is True for row in baseline['checks'])
    lan_ok = False
    if args.probe_report:
        probes = load(args.probe_report)
        lan = [row for row in probes.get('checks', []) if row.get('offlink') is False]
        lan_ok = len(lan) == 4 and all(row.get('passed') is True and row.get('echoed') is True for row in lan)
    categories = [f'IPv{family}-{proto}-offlink' for family in (4, 6) for proto in ('TCP', 'UDP')]
    leak_packets = sum(counts.get(key, {}).get('replyPayloadPacketsAfterArm', 0) for key in categories)
    attempts = all(counts.get(key, {}).get('requestPacketsAfterArm', 0) > 0 for key in categories)
    controls = baseline_ok and lan_ok and attempts
    paths = dict(pcap=args.pcap, armReport=args.arm_report, hold=args.hold, baseline=args.baseline, probeReport=args.probe_report)
    return dict(schemaVersion=1, captureSurface='isolated fixture Ethernet; fixed Windows physical fixture addresses',
                inputs={key: dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for key, path in paths.items() if path},
                connectedGuardArmedUtc=checks[0]['utc'], captureFirstUtc=utc(first), captureLastUtc=utc(last), capturedPackets=total,
                afterArmCounts=dict(sorted(counts.items())), preexistingOfflinkTCP=preexisting, applicationHold=application,
                controls=dict(baselineEightEchoes=baseline_ok, armedFourLANEchoes=lan_ok, allFourOfflinkProtocolsAttemptedAfterArm=attempts),
                offlinkReplyPayloadPacketsAfterArm=leak_packets, noOfflinkPayloadAfterArm=leak_packets == 0,
                acceptancePassed=controls and leak_packets == 0,
                limitations=['Application hold verdicts are separate from packet-level echo records; timeout can leave old TCP data queued.',
                             'This capture proves the fixed physical fixture paths only; it is not the complete leak-test matrix.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('pcap', 'arm-report', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    for option in ('hold', 'baseline', 'probe-report'):
        parser.add_argument('--' + option, type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args)
    except (ValueError, OSError, KeyError, struct.error) as error:
        raise SystemExit(str(error))
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(args.output), offlinkReplyPayloadPacketsAfterArm=report['offlinkReplyPayloadPacketsAfterArm'], acceptancePassed=report['acceptancePassed'])))


if __name__ == '__main__':
    main()
