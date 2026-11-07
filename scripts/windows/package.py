#!/usr/bin/env python3
"""Validate a complete native Windows stage, record its identity, compile Inno.

Use `prepare` before ISCC and `finish` after a successful native compilation.
The same file runs under the pinned embedded Windows Python or the Linux host.
It never publishes or signs an installer and never touches network settings.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def pe_machine(path):
    with path.open('rb') as source:
        if source.read(2) != b'MZ':
            raise ValueError(f'Not a PE file: {path}')
        source.seek(60)
        offset, = struct.unpack('<I', source.read(4))
        if offset > 16 << 20:
            raise ValueError(f'Invalid PE header: {path}')
        source.seek(offset)
        if source.read(4) != b'PE\0\0':
            raise ValueError(f'Invalid PE signature: {path}')
        return struct.unpack('<H', source.read(2))[0]


def stage_files(stage):
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'Symlinks are not allowed in the payload: {path}')
        if path.is_file() and path.name != 'build-manifest.json':
            if path.name.lower().endswith('.test.exe'):
                raise ValueError(f'Test executable in the runtime payload: {path.relative_to(stage).as_posix()}')
            yield path


def prepare(args):
    stage = args.stage.resolve()
    version = args.version or (ROOT / 'VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:\.\d+)?', version):
        raise ValueError('The product version must have 3 or 4 numeric components')
    required = [
        'vault443.exe', 'vault443d.exe', 'vault443-cli.exe',
        'vault443-access.exe', 'vault443-tunnel.exe', 'vault443-outline.exe',
        'xray.exe', 'wintun.dll', 'openvpn/openvpn.exe', 'openvpn/wintun.dll',
        'Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll', 'Qt6Network.dll',
        'Qt6Qml.dll', 'Qt6Quick.dll', 'Qt6QuickControls2.dll',
        'platforms/qwindows.dll', 'qml/QtQuick/Controls/qmldir',
        'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
        'backend-build.json', 'licenses/Vault443-LICENSE.txt',
        'licenses/THIRD-PARTY-NOTICES.txt', 'licenses/software-components.json',
        'licenses/qt/RELINKING.txt', 'INSTALLATION-en.txt', 'INSTALLATION-ru.txt',
    ]
    missing = [name for name in required if not (stage / name).is_file()]
    if missing:
        raise ValueError('Incomplete Windows payload: ' + ', '.join(missing))
    backend = load(stage / 'backend-build.json')
    if backend.get('productVersion') != version:
        raise ValueError('Product version differs from the cross-build manifest')
    for name, expected in backend.get('binaries', {}).items():
        if digest(stage / name) != expected:
            raise ValueError(f'Staged Go binary differs from its build manifest: {name}')
    components = load(stage / 'licenses/software-components.json')
    for name, identity in components.get('linkedGoBinaries', {}).items():
        if digest(stage / name) != identity['sha256']:
            raise ValueError(f'Binary differs from its collected licenses: {name}; rerun licenses.py after the final build')
    for module, patch in backend.get('dependencyPatches', {}).items():
        component = next((item for item in components['components'] if item['name'] == module), None)
        if not component or not component.get('modified') or component.get('sourcePatch') != patch:
            raise ValueError('Patched dependency provenance differs from backend manifest: ' + module)
        if (digest(stage / 'licenses' / component['patchManifest']) != patch['manifestSha256']
                or digest(stage / 'licenses' / component['patchFile']) != patch['patchSha256']):
            raise ValueError('Missing or substituted dependency patch proof: ' + module)
        sources = stage / 'licenses' / component['correspondingSources']
        source_hashes = {path.relative_to(sources).as_posix(): digest(path)
                         for path in sources.rglob('*') if path.is_file()}
        if source_hashes != patch['patchedFiles']:
            raise ValueError('Patched dependency source payload differs from backend manifest: ' + module)
    wintun = next(item for item in components['components'] if item['name'] == 'Wintun official signed prebuilt')
    if digest(stage / 'wintun.dll') != wintun['binarySha256']:
        raise ValueError('Wintun DLL differs from the official locked prebuilt DLL')
    if not any(path.is_file() for path in (stage / 'licenses/msvc').glob('*')):
        raise ValueError('Missing native MSVC runtime redistribution terms in licenses/msvc')
    toolchain = load(args.toolchain)
    if toolchain.get('sourceSha256') != digest(args.source):
        raise ValueError('Native GUI and packaging must use the same source archive; rerun the incremental gui stage')
    if not toolchain.get('msvc') or not toolchain.get('qtBasePatchSha256'):
        raise ValueError('Native toolchain manifest must include msvc and qtBasePatchSha256')
    lock = load(ROOT / 'packaging/windows/dependencies-lock.json')
    patch = next(item for item in lock['assets'] if item['name'] == 'qtbase-CVE-2026-105924.diff')
    if toolchain['qtBasePatchSha256'].lower() != patch['sha256']:
        raise ValueError('Native QtBase patch identity differs from the dependency lock')
    if not toolchain.get('qtCoreSha256') or digest(stage / 'Qt6Core.dll') != toolchain['qtCoreSha256'].lower():
        raise ValueError('QtCore DLL differs from the rebuilt native toolchain manifest')
    if toolchain.get('qtVersion') != lock['qtVersion']:
        raise ValueError('Native Qt version differs from the dependency lock')
    msvc_notices = [path.relative_to(stage / 'licenses').as_posix()
                    for path in sorted((stage / 'licenses/msvc').rglob('*')) if path.is_file()]
    components['components'] = [item for item in components['components'] if item['name'] != 'Microsoft Visual C++ Runtime']
    components['components'].append(dict(name='Microsoft Visual C++ Runtime',
        version=toolchain.get('msvcRuntimeVersion', 'See nativeToolchain and payload file identities in build-manifest.json'),
        license='LicenseRef-Microsoft-VisualCpp-Redistributable', licenseFiles=msvc_notices))
    (stage / 'licenses/software-components.json').write_text(json.dumps(components, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    files = {}
    for path in stage_files(stage):
        relative = path.relative_to(stage).as_posix()
        if path.suffix.lower() in ('.pdb', '.ilk', '.exp', '.lib'):
            raise ValueError(f'Build-only file in the runtime payload: {relative}')
        if path.suffix.lower() in ('.exe', '.dll') and pe_machine(path) != 0x8664:
            raise ValueError(f'Non-x64 PE in the runtime payload: {relative}')
        files[relative] = dict(bytes=path.stat().st_size, sha256=digest(path))
    if files['wintun.dll']['sha256'] != files['openvpn/wintun.dll']['sha256']:
        raise ValueError('OpenVPN and main VPN must use the same official pinned Wintun DLL')
    manifest = dict(
        schemaVersion=1, product='Vault 443', productVersion=version,
        platform='windows', architecture='amd64', minimumWindowsBuild=19045,
        applicationAuthenticodeSigned=False, published=False,
        source=dict(archive=args.source.name, sha256=digest(args.source)),
        backend=backend, nativeToolchain=toolchain,
        dependencyLocks={
            name: dict(sha256=digest(ROOT / 'packaging/windows' / name), contents=load(ROOT / 'packaging/windows' / name))
            for name in ('dependencies-lock.json', 'openvpn-lock.json', 'qt-source-lock.json', 'runtime-source-lock.json', 'openvpn-additional-sources-lock.json')
            if (ROOT / 'packaging/windows' / name).exists()
        }, files=files,
    )
    (stage / 'build-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Validated {len(files)} runtime files for Vault 443 {version}')
    return manifest


def finish(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = load(args.stage / 'build-manifest.json')
    version = manifest['productVersion']
    name = f'Vault443-{version}-windows-x64-setup.exe'
    installer = output / name
    if not installer.is_file():
        raise ValueError(f'Installer was not produced: {installer}')
    if pe_machine(installer) != 0x8664:
        raise ValueError('Installer is not a native x64 PE')
    shutil.copy2(args.stage / 'build-manifest.json', output / 'build-manifest.json')
    if args.source.resolve() != (output / 'source.zip').resolve():
        shutil.copy2(args.source, output / 'source.zip')
    artifacts = {
        name: dict(bytes=installer.stat().st_size, sha256=digest(installer)),
        'build-manifest.json': dict(sha256=digest(output / 'build-manifest.json')),
        'source.zip': dict(bytes=(output / 'source.zip').stat().st_size, sha256=digest(output / 'source.zip')),
    }
    (output / 'artifact-manifest.json').write_text(json.dumps(dict(
        schemaVersion=1, productVersion=version, signed=False, published=False,
        acceptance='pending', artifacts=artifacts), indent=2) + '\n', encoding='utf-8')
    (output / 'SHA256SUMS').write_text(''.join(f'{item["sha256"]}  {key}\n' for key, item in artifacts.items()), encoding='utf-8')
    print(name, artifacts[name]['sha256'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'compile', 'finish'])
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True, help='Exact working-source ZIP, outside the install payload')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/windows')
    parser.add_argument('--toolchain', type=Path, help='Native MSVC/SDK/Qt/CMake/Ninja build identities')
    parser.add_argument('--version')
    parser.add_argument('--iscc', type=Path, default=Path(r'C:\Vault443Inno\ISCC.exe'))
    args = parser.parse_args()
    if args.action in ('prepare', 'compile'):
        if args.toolchain is None:
            parser.error('--toolchain is required for prepare/compile')
        prepare(args)
    if args.action == 'compile':
        if os.name != 'nt':
            parser.error('ISCC compilation must run in the Windows build VM')
        result = subprocess.run([str(args.iscc), '--version'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode or not re.search(r'(?<![0-9.])7\.1\.1(?![0-9.])', result.stdout):
            raise ValueError('Pinned Inno Setup 7.1.1 is required')
        manifest = load(args.stage / 'build-manifest.json')
        args.output.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(args.iscc), '--quiet-progress', '--define=StageDir=' + str(args.stage.resolve()),
                        '--define=OutputDir=' + str(args.output.resolve()), '--define=AppVersion=' + manifest['productVersion'],
                        str(ROOT / 'packaging/windows/vault443.iss')], check=True)
    if args.action in ('compile', 'finish'):
        finish(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
