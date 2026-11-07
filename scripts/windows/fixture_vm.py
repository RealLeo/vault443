#!/usr/bin/env python3
"""Private Linux fixture VM; all VPN-server networking stays inside this guest."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/var/www/projects/windows'))
    parser.add_argument('action', choices=['create', 'start', 'ssh', 'put', 'get', 'poweroff'])
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = args.root.resolve()
    env = dict(os.environ, VBOX_USER_HOME=str(root / 'virtualbox'), VBOX_IPC_SOCKETID='vault443-' + str(os.getuid()))
    folder = root / 'machines' / 'vault443-fixture'
    key = root / 'fixture-ssh-key'

    def run(*command):
        subprocess.run(list(map(str, command)), env=env, check=True)

    def vbox(*arguments):
        run('VBoxManage', *arguments)

    if args.action == 'create':
        source = root / 'media' / 'ubuntu-24.04-cloud-amd64.img'
        if not source.is_file():
            raise SystemExit('Fetch the official Ubuntu cloud image using vm.py fetch first')
        if folder.exists():
            raise SystemExit('Fixture VM already exists; refusing to overwrite it')
        if not key.exists():
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'vault443-fixture-only', '-f', key)
        folder.mkdir(parents=True, mode=0o700)
        config = {
            'users': [{'name': 'vaultfixture', 'shell': '/bin/bash', 'sudo': ['ALL=(ALL) NOPASSWD:ALL'], 'lock_passwd': True, 'ssh_authorized_keys': [key.with_suffix('.pub').read_text().strip()]}],
            'ssh_pwauth': False,
            'package_update': True,
            'packages': ['openvpn', 'wireguard-tools', 'nftables', 'tcpdump', 'dnsmasq-base', 'jq', 'openssl', 'ca-certificates'],
            'write_files': [{'path': '/etc/vault443-fixture-guest', 'permissions': '0600', 'content': 'isolated Windows VPN acceptance fixture\n'}],
        }
        (folder / 'user-data').write_text('#cloud-config\n' + json.dumps(config, indent=2) + '\n')
        (folder / 'meta-data').write_text('instance-id: vault443-fixture\nlocal-hostname: vault443-fixture\n')
        network = {'version': 2, 'ethernets': {
            'management': {'match': {'macaddress': '08:00:27:44:30:01'}, 'set-name': 'mgmt0', 'dhcp4': True},
            'fixture': {'match': {'macaddress': '08:00:27:44:30:02'}, 'set-name': 'fixture0', 'addresses': ['192.0.2.1/24', '2001:db8:44::1/64']},
        }}
        (folder / 'network-config').write_text(json.dumps(network, indent=2) + '\n')
        mount = f'type=bind,src={root},dst=/work'
        disk = '/work/machines/vault443-fixture/system.vdi'
        run('docker', 'run', '--rm', '--network', 'none', '--user', f'{os.getuid()}:{os.getgid()}', '--mount', mount, 'vault443-vm-tools:local', 'qemu-img', 'convert', '-f', 'qcow2', '-O', 'vdi', '/work/media/' + source.name, disk)
        run('docker', 'run', '--rm', '--network', 'none', '--user', f'{os.getuid()}:{os.getgid()}', '--mount', mount, 'vault443-vm-tools:local', 'cloud-localds', '--network-config=/work/machines/vault443-fixture/network-config', '/work/machines/vault443-fixture/seed.iso', '/work/machines/vault443-fixture/user-data', '/work/machines/vault443-fixture/meta-data')
        vbox('createvm', '--name', 'vault443-fixture', '--basefolder', root / 'machines', '--ostype', 'Ubuntu_64', '--register')
        vbox('modifymedium', folder / 'system.vdi', '--resize', '16384')
        vbox('modifyvm', 'vault443-fixture', '--memory', '2048', '--cpus', '2', '--nic1', 'nat', '--mac-address1', '080027443001', '--nat-pf1', 'ssh,tcp,127.0.0.1,22221,,22', '--nic2', 'intnet', '--intnet2', 'vault443-test', '--mac-address2', '080027443002', '--audio-enabled', 'off')
        vbox('storagectl', 'vault443-fixture', '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci')
        vbox('storageattach', 'vault443-fixture', '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', folder / 'system.vdi')
        vbox('storageattach', 'vault443-fixture', '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'dvddrive', '--medium', folder / 'seed.iso')
    elif args.action == 'start':
        vbox('startvm', 'vault443-fixture', '--type', 'headless')
    elif args.action == 'poweroff':
        vbox('controlvm', 'vault443-fixture', 'acpipowerbutton')
    elif args.action in ['put', 'get']:
        if len(args.arguments) != 2:
            parser.error('put/get require a source and destination')
        source, destination = args.arguments
        peer = 'vaultfixture@127.0.0.1:'
        if args.action == 'put':
            destination = peer + destination
        else:
            source = peer + source
        run('scp', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', f'UserKnownHostsFile={root / "fixture-known-hosts"}', '-o', 'StrictHostKeyChecking=yes', '-P', '22221', source, destination)
    else:
        run('ssh', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no', '-o', f'UserKnownHostsFile={root / "fixture-known-hosts"}', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=5', '-p', '22221', 'vaultfixture@127.0.0.1', *args.arguments)


if __name__ == '__main__':
    main()
