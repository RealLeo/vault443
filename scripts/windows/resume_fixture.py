#!/usr/bin/env python3
"""Restage current QA servers in the already-running, isolated Linux fixture VM.

Does not start/stop a VM or renew certificates/keys. Run before Windows acceptance
after every fixture cold boot. Inputs and the last result contain no credentials.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))
import toolchain

SCRIPTS = ('fixture-server.sh', 'wireguard-fixture.sh', 'fixture-openvpn.sh')
GUEST_STAGE = '/home/vaultfixture/staging'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


PREFLIGHT = r'''
set -euo pipefail
test "$(hostname)" = vault443-fixture
test "$(cat /sys/class/dmi/id/product_name)" = VirtualBox
test "$(cat /etc/vault443-fixture-guest)" = 'isolated Windows VPN acceptance fixture'
test "$(cat /sys/class/net/fixture0/address)" = 08:00:27:44:30:02
ip -4 -j address show dev fixture0 | jq -e '.[0].addr_info | any(.local == "192.0.2.1")' >/dev/null
ip -6 -j address show dev fixture0 | jq -e '.[0].addr_info | any(.local == "2001:db8:44::1")' >/dev/null
for certificate in /fixture/ca.crt /fixture/server.crt /fixture/openvpn/client.crt; do
    openssl x509 -checkend 3600 -noout -in "$certificate" >/dev/null
done
# Refuse implicit credential regeneration by the existing setup scripts.
for key in /fixture/ca.key /fixture/server.key /fixture/client.uuid /fixture/proxy.password /fixture/openvpn/client.key /fixture/wireguard/client.key /fixture/wireguard/awg-client.key /fixture/wireguard/psk.key /fixture/wireguard/header.key /fixture/wireguard/v443srvwg.key /fixture/wireguard/v443srvwg3.key /fixture/wireguard/v443srvawg.key; do test -s "$key"; done
for binary in xray amneziawg-go; do
    test -x "/opt/vault443-fixture/bin/$binary"
    cmp -s "/opt/vault443-fixture/bin/$binary" "/home/vaultfixture/staging/$binary"
    sha256sum "/opt/vault443-fixture/bin/$binary"
done
install -d -o vaultfixture -g vaultfixture -m700 /home/vaultfixture/staging
'''

VERIFY = r'''
import ipaddress,json,subprocess,time
units=['web','xray','dns','awg','wg-web','wg-dns','openvpn','openvpn-dns','openvpn-web']
tcp={('192.0.2.1',8443),('192.0.2.1',8444),('192.0.2.1',8388),('192.0.2.1',53),('2001:db8:44::1',53),('1.1.1.1',443),('93.184.215.14',443),('93.184.215.14',8080),('2001:db8:66::14',443),('2001:db8:66::14',8080),('10.77.0.1',53),('10.77.8.10',8080),('fd77:443:8::10',8080)}
udp={('192.0.2.1',8388),('192.0.2.1',1194),('192.0.2.1',53),('2001:db8:44::1',53),('93.184.215.14',18081),('2001:db8:66::14',18081),('10.77.0.1',53)}
for a,b in [(44,80),(45,81),(46,82)]:
    for address in [f'198.19.{a}.1',f'2001:db8:{b}::1']:tcp.add((address,53));udp.add((address,53))
    for address in [f'198.19.{a}.10',f'2001:db8:{b}::10']:tcp.add((address,18080))
def sockets(protocol):
    rows=subprocess.check_output(['ss','-H','-ln'+protocol],text=True)
    result=set()
    for row in rows.splitlines():
        local=row.split()[3];address,port=local.rsplit(':',1)
        address=address.strip('[]').split('%')[0]
        try:address=str(ipaddress.ip_address(address))
        except ValueError:pass
        result.add((address,int(port)))
    return result
deadline=time.monotonic()+60
while True:
    active={unit:subprocess.run(['systemctl','is-active','--quiet','vault443-fixture-'+unit+'.service']).returncode==0 for unit in units}
    actual_tcp,actual_udp=sockets('t'),sockets('u')
    missing_tcp=sorted(tcp-actual_tcp);missing_udp=sorted(udp-actual_udp)
    awg=any(port==51821 for address,port in actual_udp)
    wg={name:subprocess.run(['wg','show',name,'listen-port'],capture_output=True,text=True) for name in ('v443srvwg','v443srvwg3')}
    wg_ok=all(wg[name].returncode==0 and wg[name].stdout.strip()==str(port) for name,port in [('v443srvwg',51820),('v443srvwg3',51822)])
    passed=all(active.values()) and not missing_tcp and not missing_udp and awg and wg_ok
    if passed or time.monotonic()>=deadline:break
    time.sleep(.5)
print(json.dumps({'passed':passed,'services':active,'missingTCP':missing_tcp,'missingUDP':missing_udp,'awgUDP51821':awg,'wireguardPortsCorrect':wg_ok,'requiredTCP':sorted(tcp),'requiredUDP':sorted(udp)}))
raise SystemExit(0 if passed else 1)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/var/www/projects/windows'))
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error('The existing private VM root is required')
    work = root / 'fixture-resume'
    work.mkdir(mode=0o700, exist_ok=True)
    result = {'startedUTC': utc(), 'completed': False, 'passed': False, 'stage': 'build', 'inputs': 'inputs.json'}

    def vm(action, *arguments, capture=False):
        return subprocess.run([sys.executable, str(REPO / 'scripts/windows/fixture_vm.py'), '--root', str(root), action, *map(str, arguments)], check=True, capture_output=capture, text=True)

    def shell(body, capture=False):
        return vm('ssh', "sudo bash -s <<'VAULT443_RESUME'\n" + body + '\nVAULT443_RESUME', capture=capture)

    try:
        go, env = toolchain.ensure(offline=True)
        env.update(GOOS='linux', GOARCH='amd64', CGO_ENABLED='0', GOPROXY='off')
        binary = work / 'e2e-fixture'
        subprocess.run([str(go), 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-o', str(binary), './tests/e2e/fixture'], cwd=REPO, env=env, check=True)
        source_paths = [REPO / 'go.mod', REPO / 'go.sum', REPO / 'packaging/go-toolchain-lock.json', *sorted((REPO / 'tests/e2e/fixture').glob('*.go'))]
        staged = [(REPO / 'tests/windows' / name, name) for name in SCRIPTS] + [(binary, 'e2e-fixture')]
        manifest = {'createdUTC': utc(), 'goVersion': toolchain.LOCK['version'], 'build': ['GOOS=linux', 'GOARCH=amd64', 'CGO_ENABLED=0', 'GOPROXY=off', 'go build -mod=readonly -trimpath -buildvcs=false ./tests/e2e/fixture'], 'sourceInputs': [{'path': str(path.relative_to(REPO)), 'sha256': sha(path)} for path in source_paths], 'stagedInputs': [{'name': name, 'bytes': path.stat().st_size, 'sha256': sha(path)} for path, name in staged]}
        (work / 'inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')
        result['stage'] = 'guest-preflight'
        checked = shell(PREFLIGHT, capture=True)
        manifest['retainedGuestBinaries'] = []
        for line in checked.stdout.splitlines():
            digest, name = line.split()
            manifest['retainedGuestBinaries'].append({'path': name, 'sha256': digest})
        (work / 'inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')
        result['inputManifestSHA256'] = sha(work / 'inputs.json')
        result['stage'] = 'stage-current-inputs'
        for path, name in staged:
            vm('put', path, GUEST_STAGE + '/' + name, capture=True)
        checks = '\n'.join(f"echo '{sha(path)}  {GUEST_STAGE}/{name}' | sha256sum --check --status" for path, name in staged)
        shell('set -euo pipefail\n' + checks, capture=True)
        # The legacy setup scripts install binaries before stopping their units.
        # Stop only these owned units first so a warm resume cannot hit ETXTBSY.
        result['stage'] = 'stop-owned-binary-users'
        shell('''set -euo pipefail
for name in web xray awg; do
    unit="vault443-fixture-$name.service"
    if test "$(systemctl show -p LoadState --value "$unit")" != not-found; then systemctl stop "$unit"; fi
done''', capture=True)
        for name in SCRIPTS:
            result['stage'] = name
            print('Resume fixture:', name, flush=True)
            shell(f'set -euo pipefail\nbash {GUEST_STAGE}/{name}', capture=True)
        result['stage'] = 'verify-services-and-listeners'
        # Save the bounded JSON verification even on a missing listener.
        try:
            verified = shell("python3 - <<'PY'\n" + VERIFY + '\nPY', capture=True)
        except subprocess.CalledProcessError as error:
            if error.stdout:
                try:
                    result['verification'] = json.loads(error.stdout)
                except ValueError:
                    pass
            raise
        result['verification'] = json.loads(verified.stdout)
        result['passed'] = result['verification']['passed']
        result['stage'] = 'complete'
    except Exception as error:
        result['errorType'] = type(error).__name__
        # Captured guest output is deliberately excluded: setup owns credentials.
        print('Fixture resume failed at', result['stage'], '(' + type(error).__name__ + ')', file=sys.stderr)
    finally:
        result.update(completed=True, finishedUTC=utc())
        (work / 'last-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'passed': result['passed'], 'stage': result['stage'], 'report': str(work / 'last-result.json')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
