#!/usr/bin/env python3
"""Collect notices and matching sources for the exact Windows payload.

Run on the Linux build host with the project's locked Go. --fetch only downloads
missing Go modules; their h1 sums must match the linked executable's BuildInfo.
Qt/runtime source archives are independently SHA-256 locked and supplied by SDK.
No test credentials, VM disks or host configuration are copied.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
wf_spec = importlib.util.spec_from_file_location('wf_patch', ROOT / 'scripts/windows/wf_patch.py')
wf_patch = importlib.util.module_from_spec(wf_spec)
wf_spec.loader.exec_module(wf_patch)
spec = importlib.util.spec_from_file_location('toolchain', ROOT / 'scripts/toolchain.py')
toolchain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toolchain)


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        destination.unlink()
    shutil.copy2(source, destination)
    return dict(file=destination.name, sha256=sha256(destination))


def escape_module(value):
    return ''.join('!' + c.lower() if c.isupper() else c for c in value)


def notice_file(path):
    name = path.name.upper()
    return any(name == prefix or name.startswith(prefix + '.') or name.startswith(prefix + '-')
               for prefix in ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'PATENTS', 'AUTHORS'))


def locked_asset(sdk, asset, fetch=False):
    path = sdk / 'media' / asset['name']
    if not path.exists() and fetch:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.partial')
        try:
            with urllib.request.urlopen(asset['url'], timeout=60) as source, temporary.open('wb') as output:
                remaining = asset['bytes']
                while chunk := source.read(min(4 << 20, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError('Oversized dependency download: ' + asset['name'])
                    output.write(chunk)
            if sha256(temporary) != asset['sha256']:
                raise ValueError('Source/dependency checksum mismatch: ' + asset['name'])
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if not path.is_file() or sha256(path) != asset['sha256']:
        raise ValueError('Missing or mismatched source/dependency archive: ' + asset['name'])
    return path


def binary_modules(go, env, binary):
    output = subprocess.check_output([str(go), 'version', '-m', str(binary)], env=env, text=True)
    lines = output.splitlines()
    version = lines[0].rsplit(': ', 1)[-1]
    modules = []
    replacements = set()
    pending = None
    for line in lines[1:]:
        fields = line.split('\t')
        if len(fields) >= 4 and fields[1] == 'dep':
            if pending is not None:
                raise ValueError('Dependency without a linked h1 or reviewed replacement')
            pending = tuple((fields + [''])[2:5])
            if pending[2]:
                modules.append(pending)
                pending = None
        elif len(fields) >= 2 and fields[1] == '=>':
            if (pending is None or pending[:2] != (wf_patch.MODULE, wf_patch.VERSION)
                    or len(fields) < 4 or fields[2:4] != [wf_patch.REPLACEMENT, '(devel)']):
                raise ValueError('Replaced dependency requires explicit licensing review: ' + line)
            wf_patch.verify(ROOT)
            modules.append((wf_patch.MODULE, wf_patch.VERSION, wf_patch.SUM))
            replacements.add(wf_patch.MODULE)
            pending = None
    if pending is not None:
        raise ValueError('Dependency without a linked h1 or reviewed replacement')
    return version, modules, replacements


def module_info(go, env, caches, module, version, expected_sum, allow_fetch):
    encoded = escape_module(module)
    for cache in caches:
        directory = cache / (encoded + '@' + version)
        sum_file = cache / 'cache/download' / encoded / '@v' / (version + '.ziphash')
        if directory.is_dir() and sum_file.is_file() and sum_file.read_text().strip() == expected_sum:
            return directory
    if not allow_fetch:
        raise ValueError(f'Missing verified license module {module}@{version}; rerun licenses.py with --fetch')
    environment = dict(env, GOMODCACHE=str(ROOT / '.cache/windows-license-modules'), GOPROXY='https://proxy.golang.org,direct', GOSUMDB='off')
    # The independently locked upstream binary supplies the expected h1.
    # Compare the computed module zip sum below; no mutable sumdb lookup is
    # needed to identify license sources already pinned by that binary.
    process = subprocess.run([str(go), 'mod', 'download', '-json', module + '@' + version],
                             cwd=ROOT / '.cache/windows-license-work', env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        info = json.loads(process.stdout)
    except json.JSONDecodeError:
        raise ValueError(f'Could not download license sources for {module}@{version}')
    if process.returncode or info.get('Error') or info.get('Sum') != expected_sum:
        raise ValueError(f'Go module identity mismatch/download error for {module}@{version}: {info.get("Error", "")}')
    return Path(info['Dir'])


def collect(args):
    go, env = toolchain.ensure(offline=True)
    work = ROOT / '.cache/windows-license-work'
    work.mkdir(parents=True, exist_ok=True)
    (work / 'go.mod').write_text('module vault443/windows-license-sources\n\ngo 1.27.0\n')
    asset_path = lambda asset: locked_asset(args.sdk, asset, args.fetch)
    stage = args.stage.resolve()
    output = stage / 'licenses'
    output.mkdir(parents=True, exist_ok=True)
    components = []
    copy(ROOT / 'LICENSE', output / 'Vault443-LICENSE.txt')
    for path in (ROOT / 'assets/fonts').iterdir():
        if notice_file(path) or 'LICENSE' in path.name:
            copy(path, output / 'fonts' / path.name)
    go_root = Path(env['GOROOT'])
    for source in sorted(go_root.rglob('*')):
        if source.is_file() and notice_file(source):
            copy(source, output / 'go/runtime' / source.relative_to(go_root))
    components.append(dict(name='Vault 443', version=(ROOT / 'VERSION').read_text().strip(), license='MIT',
                           licenseFiles=['Vault443-LICENSE.txt']))
    components.append(dict(name='Go toolchain/runtime', version=toolchain.LOCK['version'], license='BSD-3-Clause',
                           licenseFiles=['go/runtime/LICENSE']))
    components.extend([
        dict(name='Roboto Condensed', license='Apache-2.0', licenseFiles=['fonts/Roboto-LICENSE.txt']),
        dict(name='Iosevka Term', license='OFL-1.1', licenseFiles=['fonts/Iosevka-LICENSE.md']),
    ])
    dependency_lock = json.loads((ROOT / 'packaging/windows/dependencies-lock.json').read_text())
    with zipfile.ZipFile(asset_path(next(a for a in dependency_lock['assets'] if a['name'] == 'wintun-0.14.1.zip'))) as archive:
        (output / 'Wintun-Prebuilt-LICENSE.txt').write_bytes(archive.read('wintun/LICENSE.txt'))
        wintun_hash = hashlib.sha256(archive.read('wintun/bin/amd64/wintun.dll')).hexdigest()
    components.append(dict(name='Wintun official signed prebuilt', version='0.14.1', license='LicenseRef-Wintun-Prebuilt',
                           licenseFiles=['Wintun-Prebuilt-LICENSE.txt'], modified=False,
                           binarySha256=wintun_hash))
    binaries = sorted(args.binaries.glob('vault443*.exe'))
    xray = ROOT / '.cache/windows-licenses/xray.exe'
    xray.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(asset_path(next(a for a in dependency_lock['assets'] if a['name'] == 'xray-windows-x64.zip'))) as archive:
        xray.write_bytes(archive.read('xray.exe'))
        (output / 'Xray-LICENSE.txt').write_bytes(archive.read('LICENSE'))
    binaries.append(xray)
    if len(binaries) < 6:
        raise ValueError('Build all five project Go executables before collecting licenses')
    modules = {}
    linked_binaries = {}
    patched_binaries = set()
    for binary in binaries:
        version, dependencies, replacements = binary_modules(go, env, binary)
        if wf_patch.MODULE in replacements:
            patched_binaries.add(binary.name)
        linked_binaries[binary.name] = dict(goVersion=version, sha256=sha256(binary))
        for module, module_version, module_sum in dependencies:
            key = (module, module_version, module_sum)
            modules.setdefault(key, set()).add(binary.name)
    caches = [ROOT / '.cache/go-mod', ROOT / '.cache/outline/modules', ROOT / '.cache/windows-license-modules']

    def collect_module(item):
        (module, version, module_sum), users = item
        directory = module_info(go, env, caches, module, version, module_sum, args.fetch)
        slug = re.sub('[^A-Za-z0-9._-]', '_', module) + '-' + hashlib.sha256((module + '@' + version).encode()).hexdigest()[:12]
        target = output / 'go/modules' / slug
        notices = []
        for source in sorted(directory.rglob('*')):
            if source.is_file() and notice_file(source):
                if source.stat().st_size > 2 << 20:
                    raise ValueError('Oversized license notice: ' + str(source))
                destination = target / source.relative_to(directory)
                copy(source, destination)
                notices.append(str(destination.relative_to(output)).replace(os.sep, '/'))
        if not notices:
            raise ValueError(f'No license notices found for {module}@{version}')
        component = dict(name=module, version=version, goModuleSum=module_sum, binaries=sorted(users),
                         license='SEE-LICENSE-FILES', licenseFiles=notices)
        if module == wf_patch.MODULE and users & patched_binaries:
            reviewed = wf_patch.verify(ROOT)
            proof = output / 'go/patched/wf'
            copy(ROOT / reviewed['manifestFile'], proof / 'wf-patch.json')
            copy(ROOT / reviewed['patchFile'], proof / 'wfp-abi-and-alignment.patch')
            for relative in reviewed['patchedFiles']:
                copy(ROOT / 'third_party/wf' / relative, proof / 'source' / relative)
            component.update(modified=True, modifiedBinaries=sorted(users & patched_binaries),
                             upstreamVersion=wf_patch.VERSION, upstreamModuleSum=wf_patch.SUM,
                             sourcePatch=reviewed, correspondingSources='go/patched/wf/source',
                             patchManifest='go/patched/wf/wf-patch.json',
                             patchFile='go/patched/wf/wfp-abi-and-alignment.patch')
        return component

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        components.extend(executor.map(collect_module, sorted(modules.items())))
    qt_sources = json.loads((ROOT / 'packaging/windows/qt-source-lock.json').read_text())
    source_assets = [a for a in dependency_lock['assets'] if a['name'] in
                     ('qtbase-everywhere-src-6.12.0.tar.xz', 'qtbase-CVE-2026-105924.diff')]
    source_assets += qt_sources['assets']
    for asset in source_assets:
        source = asset_path(asset)
        copy(source, output / 'qt/sources' / source.name)
        if source.name.endswith('.tar.xz'):
            module = source.name.split('-everywhere-')[0]
            with tarfile.open(source) as archive:
                for member in archive.getmembers():
                    path = Path(member.name)
                    if not member.isfile() or 'LICENSES' not in path.parts:
                        continue
                    # Only copy canonical text notices; matching source is also bundled.
                    if member.size > 2 << 20:
                        raise ValueError('Oversized Qt license text')
                    content = archive.extractfile(member)
                    target = output / 'qt/texts' / module / path.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content.read())
    qt_metadata = output / 'qt/upstream-sbom'
    qt_metadata.mkdir(parents=True, exist_ok=True)
    for module in ('qtbase', 'qtdeclarative', 'qtshadertools'):
        source = args.sdk / 'qt/sbom' / f'{module}-6.12.0.spdx.json'
        if not source.exists():
            raise ValueError('Missing upstream Qt SBOM: ' + str(source))
        copy(source, qt_metadata / source.name)
        document = json.loads(source.read_text(encoding='utf-8-sig'))
        texts = output / 'qt/attributions' / module
        texts.mkdir(parents=True, exist_ok=True)
        for item in document.get('hasExtractedLicensingInfos', []):
            name = re.sub('[^A-Za-z0-9._-]', '_', item['licenseId'])
            (texts / (name + '.txt')).write_text(item.get('name', item['licenseId']) + '\n\n' + item['extractedText'] + '\n', encoding='utf-8')
        components.append(dict(name=module, version='6.12.0', license='LGPL-3.0-only',
                               upstreamSPDX='qt/upstream-sbom/' + source.name, upstreamMetadataOnly=True,
                               modified=(module == 'qtbase'),
                               thirdPartyLicenseDetail='See the upstream SPDX component list and qt/attributions.',
                               correspondingSources=[a for a in source_assets if a['name'].startswith(module + '-')]))
    (output / 'qt/RELINKING.txt').write_text('''Vault 443 uses Qt 6.12.0 through shared DLLs under LGPL-3.0-only.
Copyright (C) The Qt Company Ltd. and the contributors named in the included sources.
Qt DLLs are installed alongside the application and are not statically linked.
You may replace them with interface-compatible modified Qt DLLs; Vault 443 does
not verify or prohibit replacement of Qt DLLs. Administrator access is needed
for writing Program Files. Reverse engineering for debugging modifications to
Qt is permitted as required by the applicable license.

The matching QtBase, QtDeclarative and Qt Shader Tools sources and the exact
QtBase CVE-2026-105924 patch are bundled under qt/sources. QtBase is modified by
that published patch; the remaining bundled Qt libraries are official prebuilt
6.12.0 MSVC2022 x64 libraries. The upstream SBOM files preserve component-level
copyright and license attributions. The application source archive, native
build script and build manifest accompany the installer distribution.

Rebuild with MSVC 2022 using scripts/windows/native-build.ps1, applying the
included QtBase patch as scripts/windows/prepare_sdk.py does. LGPL-3.0-only and
GPL-3.0-only license texts are included under qt/texts. For original Qt source
releases: https://download.qt.io/official_releases/qt/6.12/6.12.0/submodules/
''', encoding='utf-8')
    runtime_lock = json.loads((ROOT / 'packaging/windows/runtime-source-lock.json').read_text())
    for asset in runtime_lock['assets']:
        source = asset_path(asset)
        copy(source, output / 'xray/sources' / source.name)
    components.append(dict(name='Xray-core', version='26.9.30', license='MPL-2.0',
                           licenseFiles=['Xray-LICENSE.txt'], correspondingSources=runtime_lock['assets']))
    additional_lock = ROOT / 'packaging/windows/openvpn-additional-sources-lock.json'
    if additional_lock.exists():
        additional = json.loads(additional_lock.read_text())
        for asset in additional['assets']:
            source = asset_path(asset)
            copy(source, output / 'openvpn-additional/sources' / source.name)
            module = 'OpenSSL' if source.name.startswith('openssl-') else 'LZ4'
            with tarfile.open(source) as archive:
                notice_paths = []
                for member in archive.getmembers():
                    path = Path(member.name)
                    if not member.isfile() or not notice_file(path):
                        continue
                    # Preserve all upstream notices without extracting code.
                    if member.size > 2 << 20:
                        raise ValueError('Oversized runtime dependency notice')
                    target = output / 'openvpn-additional/texts' / module / Path(*path.parts[1:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
                    notice_paths.append(target.relative_to(output).as_posix())
            components.append(dict(name=module, version='3.6.5' if module == 'OpenSSL' else '1.10.0',
                                   license='Apache-2.0' if module == 'OpenSSL' else 'BSD-2-Clause',
                                   licenseFiles=notice_paths, correspondingSources=[asset]))
    if (ROOT / 'packaging/windows/openvpn-lock.json').exists():
        openvpn = json.loads((ROOT / 'packaging/windows/openvpn-lock.json').read_text())
        copy(ROOT / 'packaging/windows/openvpn-lock.json', output / 'openvpn-lock.json')
        components.append(dict(name='OpenVPN Windows runtime', license='SEE-LICENSE-FILES',
                               details='Runtime licenses and corresponding sources are bundled under openvpn/.',
                               dependencyLock=openvpn))
    (output / 'software-components.json').write_text(json.dumps(dict(
        schemaVersion=1, projectVersion=(ROOT / 'VERSION').read_text().strip(),
        linkedGoBinaries=linked_binaries, components=components), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (output / 'THIRD-PARTY-NOTICES.txt').write_text('''Vault 443 third-party components

Vault 443 source is MIT licensed. This distribution also contains Qt shared
libraries (LGPL-3.0-only), Xray-core (MPL-2.0), the official signed Wintun DLL
under its prebuilt-binaries license, OpenVPN and its dependencies under their
included licenses, Go runtime and libraries, and bundled fonts. Each component
retains its own license; the application license does not replace those terms.

software-components.json records the exact linked Go module versions, h1
module identities, binary hashes and notice locations. Qt's upstream SPDX SBOM
and extracted license texts preserve its bundled dependency attributions.
Corresponding Qt and Xray sources are included in this installation. OpenVPN
and other runtime corresponding sources and notices are in openvpn/ and
licenses/openvpn-additional/.

Qt linking and replacement instructions: qt/RELINKING.txt.
Roboto Condensed: Apache-2.0; Iosevka Term: SIL Open Font License 1.1.
Official Wintun DLLs are unmodified and are accessed through the published API.
MSVC runtime files remain subject to Microsoft's included redistribution terms.
''', encoding='utf-8')
    (stage / 'INSTALLATION-en.txt').write_text('''Vault 443 is ready.

Open Vault 443 from the Start menu. The VPN service works in the background;
the interface runs as your normal Windows user. Administrator approval is
required for administrative actions.

Your profiles are preserved when the application is updated or removed.
The installer restores application-owned networking before removing files.
If restoration fails, it retains the application so you can retry safely.
Third-party notices and corresponding sources are installed in licenses/.
''', encoding='utf-8')
    (stage / 'INSTALLATION-ru.txt').write_text('''Vault 443 готов к работе.

Откройте Vault 443 из меню «Пуск». Служба VPN работает в фоне, а интерфейс —
от обычного пользователя Windows. Административные действия требуют
подтверждения прав администратора.

При обновлении и удалении приложения профили сохраняются. Перед удалением
файлов установщик восстанавливает сетевые настройки приложения. Если это
не удалось, файлы сохраняются для повторной попытки.
Лицензии сторонних компонентов и их исходники установлены в licenses/.
''', encoding='utf-8')
    print(f'Collected notices for {len(modules)} linked Go modules and Qt/runtime sources into {output}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, default=Path('/var/www/projects/windows/sdk'))
    parser.add_argument('--binaries', type=Path, default=ROOT / 'build-windows')
    parser.add_argument('--fetch', action='store_true', help='Download missing Go module sources and verify their linked h1 sums')
    args = parser.parse_args()
    collect(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
