#!/usr/bin/env python3
"""Reproducible, project-private VirtualBox Windows acceptance machines.

Run on the Linux host. Credentials and VM state stay outside the source tree.
No existing VirtualBox registrations or host network adapters are changed.
"""
import argparse
import base64
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request

MEDIA = {
    'win10': ('windows10-22h2-eval-x64.iso', 'https://software-static.download.prss.microsoft.com/dbazure/988969d5-f34g-4e03-ac9d-1f9786c66750/19045.2006.220908-0225.22h2_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso', 5550497792),
    'win11': ('windows11-25h2-eval-x64.iso', 'https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26200.6584.250915-1905.25h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso', 7092807680),
    'additions': ('VBoxGuestAdditions_7.0.16.iso', 'https://download.virtualbox.org/virtualbox/7.0.16/VBoxGuestAdditions_7.0.16.iso', None),
    'fixture': ('ubuntu-24.04-cloud-amd64.img', 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img', 621284352),
}


def fetch(item, root, chunk_bytes=0):
    lock_path = root / 'media' / (item[1][0] + '.lock')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return download(item, root, chunk_bytes)


def download(item, root, chunk_bytes=0):
    name, (filename, url, size) = item
    path = root / 'media' / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        temporary = path.with_suffix('.partial')
        offset = temporary.stat().st_size if temporary.exists() else 0
        end = str(offset + chunk_bytes - 1) if chunk_bytes else ''
        request = urllib.request.Request(url, headers={'Range': f'bytes={offset}-{end}'} if offset or chunk_bytes else {})
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 206:
                offset = 0
            with temporary.open('ab' if offset else 'wb') as output:
                received = 0
                while chunk := response.read(4 << 20):
                    output.write(chunk)
                    received += len(chunk)
                    if chunk_bytes and received >= chunk_bytes:
                        break
        if chunk_bytes and size and temporary.stat().st_size < size:
            print(f'{name}: resumed {temporary.stat().st_size}/{size} bytes', flush=True)
            return
        if size and temporary.stat().st_size != size:
            raise RuntimeError(f'{name}: unexpected download length')
        temporary.replace(path)
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    manifest = dict(url=url, bytes=path.stat().st_size, sha256=digest)
    record = path.with_suffix('.json')
    if record.exists() and json.loads(record.read_text()) != manifest:
        raise RuntimeError(f'{name}: cached media differs from its recorded identity')
    record.write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'{name}: {path.name} sha256={digest}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/var/www/projects/windows'))
    parser.add_argument('--username', choices=['vaultqa', 'vaultqa2'], default='vaultqa',
                        help='GuestControl user; vaultqa2 requires an existing guest-password-qa2 file')
    parser.add_argument('--chunk-mib', type=int, default=0, help='bound each ISO download invocation; rerun to resume')
    parser.add_argument('action', choices=['fetch', 'create', 'start', 'status', 'exec', 'ps', 'put', 'get', 'screenshot', 'poweroff'])
    parser.add_argument('machine', nargs='?', choices=['win10', 'win11'])
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.username != 'vaultqa' and args.action not in ('exec', 'ps', 'put', 'get'):
        parser.error('--username vaultqa2 is supported only for exec, ps, put and get')
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    registry = root / 'virtualbox'
    registry.mkdir(exist_ok=True, mode=0o700)
    env = dict(os.environ, VBOX_USER_HOME=str(registry), VBOX_IPC_SOCKETID='vault443-' + str(os.getuid()))
    password_file = root / ('guest-password-qa2' if args.username == 'vaultqa2' else 'guest-password')
    if not password_file.exists():
        if args.username == 'vaultqa2':
            raise SystemExit('Prepare guest-password-qa2 separately before using vaultqa2')
        fd = os.open(password_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(secrets.token_urlsafe(24) + '\n')
    password = password_file.read_text().strip()

    def vbox(*arguments):
        result = subprocess.run(['VBoxManage', *map(str, arguments)], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout.replace(password, '<private>'), end='', flush=True)
        result.check_returncode()
        return result.stdout

    if args.action == 'fetch':
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            list(executor.map(lambda item: fetch(item, root, args.chunk_mib << 20), MEDIA.items()))
        return
    if args.action == 'status':
        vbox('list', 'vms')
        vbox('list', 'runningvms')
        return
    if not args.machine:
        parser.error('machine is required')
    name = 'vault443-' + args.machine
    folder = root / 'machines' / name
    if args.action == 'create':
        if folder.exists():
            raise SystemExit(f'{folder} already exists; refusing to overwrite a VM')
        iso = root / 'media' / MEDIA[args.machine][0]
        additions = root / 'media' / MEDIA['additions'][0]
        if not iso.is_file() or not additions.is_file():
            raise SystemExit('Run fetch first')
        vbox('createvm', '--name', name, '--basefolder', root / 'machines', '--ostype', 'Windows11_64' if args.machine == 'win11' else 'Windows10_64', '--register')
        vbox('modifyvm', name, '--memory', '6144', '--cpus', '4', '--vram', '128', '--graphicscontroller', 'vboxsvga', '--accelerate-3d', 'off', '--ioapic', 'on', '--firmware', 'efi', '--nic1', 'nat', '--audio-enabled', 'off', '--clipboard-mode', 'disabled', '--drag-and-drop', 'disabled', '--boot1', 'dvd', '--boot2', 'disk')
        vbox('modifynvram', name, 'inituefivarstore')
        vbox('modifynvram', name, 'enrollmssignatures')
        vbox('modifynvram', name, 'enrollorclpk')
        if args.machine == 'win11':
            vbox('modifyvm', name, '--tpm-type', '2.0')
        disk = folder / 'system.vdi'
        vbox('createmedium', 'disk', '--filename', disk, '--size', '81920', '--format', 'VDI')
        vbox('storagectl', name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci')
        vbox('storageattach', name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', disk)
        vbox('unattended', 'install', name, '--iso', iso, '--user', 'vaultqa', '--password-file', password_file, '--full-user-name', 'Vault 443 QA', '--hostname', name + '.test', '--locale', 'en_US', '--language', 'en-US', '--country', 'US', '--time-zone', 'UTC', '--install-additions', '--additions-iso', additions, '--image-index', '1', '--post-install-command', 'sc.exe config VBoxService start= auto & sc.exe start VBoxService')
        (folder / 'install-pending').touch()
    elif args.action == 'start':
        running = vbox('list', 'runningvms')
        if any('"vault443-' + windows + '"' in running for windows in ['win10', 'win11']):
            raise SystemExit('A project VM is already running; run Windows acceptance machines sequentially')
        vbox('startvm', name, '--type', 'headless')
        pending = folder / 'install-pending'
        if pending.exists():
            # Microsoft's UEFI DVD loader requires a key even with an answer
            # file. Send Space only on the initial installation boot.
            for _ in range(16):
                time.sleep(.5)
                vbox('controlvm', name, 'keyboardputscancode', '39', 'b9')
            pending.unlink()
    elif args.action in ['exec', 'ps']:
        if not args.arguments:
            parser.error('exec needs an absolute guest executable and its arguments')
        if args.action == 'ps':
            if len(args.arguments) != 1:
                parser.error('ps requires one PowerShell script string')
            executable = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            script = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" + args.arguments[0]
            encoded = base64.b64encode(script.encode('utf-16le')).decode()
            arguments = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]
        else:
            executable, *arguments = args.arguments
        # Explicit argv[0]: otherwise native Go tests stop parsing flags at the
        # duplicated executable and PowerShell launches an unnecessary child.
        vbox('guestcontrol', name, 'run', '--username', args.username, '--passwordfile', password_file, '--exe', executable, '--arg0', executable, '--wait-stdout', '--wait-stderr', '--timeout', '60000', '--', *arguments)
    elif args.action in ['put', 'get']:
        if len(args.arguments) != 2:
            parser.error('put/get need a source and destination')
        vbox('guestcontrol', name, 'copyto' if args.action == 'put' else 'copyfrom', '--username', args.username, '--passwordfile', password_file, '--recursive', *args.arguments)
    elif args.action == 'screenshot':
        output = root / 'screenshots'
        output.mkdir(exist_ok=True)
        vbox('controlvm', name, 'screenshotpng', output / (args.machine + '.png'))
    elif args.action == 'poweroff':
        vbox('controlvm', name, 'acpipowerbutton')


if __name__ == '__main__':
    main()
