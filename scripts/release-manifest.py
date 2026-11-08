#!/usr/bin/env python3
"""Inventory the six release installers; never infer Windows acceptance.

Preview: python3 scripts/release-manifest.py --output dist/release-1.3.5
Final: add --windows-dir dist/windows/1.3.5/<validated-candidate> --require-all

Installers stay at their existing paths. The output contains public checksum
sidecars, copied build manifests, the validation report and release-manifest.json.
No candidate is selected automatically and no upload or publication is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def local_path(path):
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows-dir', type=Path, help='Explicit final Windows candidate directory')
    parser.add_argument('--output', type=Path, required=True, help='Output directory beneath project dist/')
    parser.add_argument('--validation-report', type=Path)
    parser.add_argument('--require-all', action='store_true', help='Fail before writing unless all six installers are supplied')
    args = parser.parse_args()
    version = (ROOT / 'VERSION').read_text().strip()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / 'dist') or output == ROOT / 'dist':
        parser.error('--output must be a child directory of project dist/')
    windows_name = f'Vault443-{version}-windows-x64-setup.exe'
    specs = [
        ('windows-x64', windows_name, args.windows_dir.resolve() / windows_name if args.windows_dir else None),
        ('ubuntu-x64', f'vault443_{version}-1ubuntu24.04_amd64.deb', ROOT / f'dist/linux/ubuntu24/vault443_{version}-1ubuntu24.04_amd64.deb'),
        ('ubuntu-arm64', f'vault443_{version}_arm64.deb', ROOT / f'dist/vault443_{version}_arm64.deb'),
        ('debian13-x64', f'vault443_{version}-1debian13_amd64.deb', ROOT / f'dist/linux/debian13/vault443_{version}-1debian13_amd64.deb'),
        ('fedora44-x64', f'vault443-{version}-1.fc44.x86_64.rpm', ROOT / f'dist/linux/fedora44/vault443-{version}-1.fc44.x86_64.rpm'),
        ('arch-x64', f'vault443-{version}-1-x86_64.pkg.tar.zst', ROOT / f'dist/linux/arch/vault443-{version}-1-x86_64.pkg.tar.zst'),
    ]
    expected = {name for _, name, _ in specs}
    for readme in ('README.md', 'README.ru.md'):
        links = set(re.findall(r'https://github\.com/RealLeo/vault443/releases/download/' + re.escape(version) + r'''/([^\s)>"']+)''', (ROOT / readme).read_text()))
        installers = {name for name in links if name.endswith(('.exe', '.deb', '.rpm', '.pkg.tar.zst'))}
        if installers != expected or not {name + '.sha256' for name in expected} <= links:
            raise ValueError(f'{readme}: installer/checksum filenames differ from the six release assets')
    report = (args.validation_report or ROOT / f'docs/VALIDATION-{version}.md').resolve()
    report_bytes = report.read_bytes()
    assets, missing, writes = [], [], {}
    for platform, name, path in specs:
        entry = dict(platform=platform, name=name, checksumName=name + '.sha256')
        if path is None or not path.is_file():
            entry['artifactStatus'] = 'missing'
            missing.append(name)
            assets.append(entry)
            continue
        sha = digest(path)
        if platform == 'windows-x64':
            artifact_path = path.parent / 'artifact-manifest.json'
            artifact = load(artifact_path)
            record = artifact['artifacts'][name]
            build_path = path.parent / 'build-manifest.json'
            if artifact['productVersion'] != version or record['sha256'] != sha or record['bytes'] != path.stat().st_size:
                raise ValueError('Windows installer differs from its artifact manifest')
            if digest(build_path) != artifact['artifacts']['build-manifest.json']['sha256']:
                raise ValueError('Windows build manifest differs from its artifact manifest')
            build = load(build_path)
            if build['productVersion'] != version or build['platform'] != 'windows' or build['architecture'] != 'amd64':
                raise ValueError('Windows build manifest version/platform mismatch')
        else:
            checksum = Path(str(path) + '.sha256').read_text().split()
            if checksum != [sha, name]:
                raise ValueError('Checksum sidecar mismatch: ' + name)
            build_path = Path(str(path) + '.build.json')
            build = load(build_path)
            if build['productVersion'] != version or build['package'] != name or build['sha256'] != sha:
                raise ValueError('Linux build manifest mismatch: ' + name)
        build_name = name + '.build.json'
        build_bytes = build_path.read_bytes()
        entry.update(artifactStatus='inventoried', path=local_path(path), bytes=path.stat().st_size, sha256=sha,
                     buildManifest=build_name, buildManifestSHA256=hashlib.sha256(build_bytes).hexdigest())
        assets.append(entry)
        writes[entry['checksumName']] = (sha + '  ' + name + '\n').encode()
        writes[build_name] = build_bytes
    if args.require_all and missing:
        raise ValueError('Incomplete installer set: ' + ', '.join(missing))
    inventory = dict(schemaVersion=1, productVersion=version, artifactSetComplete=not missing,
                     expectedInstallerCount=6, inventoriedInstallerCount=6 - len(missing), missing=missing,
                     validationNote='Artifact hashes do not assert Windows acceptance; consult the separate validation report.',
                     validationReport=dict(name=report.name, sha256=hashlib.sha256(report_bytes).hexdigest()),
                     readmeFilenamesVerified=['README.md', 'README.ru.md'], assets=assets)
    writes['SHA256SUMS'] = ''.join(a['sha256'] + '  ' + a['name'] + '\n' for a in assets if 'sha256' in a).encode()
    writes[report.name] = report_bytes
    writes['release-manifest.json'] = (json.dumps(inventory, indent=2) + '\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    for name, data in writes.items():
        temporary = output / (name + '.tmp')
        temporary.write_bytes(data)
        temporary.replace(output / name)
    print(json.dumps(dict(output=str(output), inventoried=6 - len(missing), missing=missing,
                          windowsAcceptance='not asserted'), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(str(error))
