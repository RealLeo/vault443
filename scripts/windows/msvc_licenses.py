#!/usr/bin/env python3
"""Extract EN/RU redistribution terms from the installed MSVC's official bundle.

Copy VC_redist.x64.exe from the pinned native toolchain to the Linux host first.
This reads the Burn CAB; it never runs or installs the redistributable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def extract(archive, member):
    return subprocess.check_output(['cabextract', '-p', '-F', member, str(archive)],
                                   stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--redistributable', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    archive = args.redistributable
    archive_sha = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    if archive_sha != args.expected_sha256.lower():
        parser.error('Redistributable differs from the native toolchain receipt')
    manifest = extract(archive, '0')
    root = ET.fromstring(manifest)
    payloads = {node.attrib['FilePath'].replace('\\\\', '/').replace('\\', '/'): node.attrib
                for node in root.iter() if node.tag.endswith('}Payload')}
    output = args.stage / 'licenses/msvc'
    output.mkdir(parents=True, exist_ok=True)
    files = {}
    for original, name in [('license.rtf', 'VC-Runtime-EULA-en.rtf'),
                           ('1049/license.rtf', 'VC-Runtime-EULA-ru.rtf')]:
        info = payloads[original]
        member = info['SourcePath']
        if not member.startswith('u') or not member[1:].isdigit():
            raise ValueError('Unexpected Burn embedded member')
        data = extract(archive, member)
        if len(data) != int(info['FileSize']) or hashlib.sha1(data).hexdigest().upper() != info['Hash'].upper():
            raise ValueError('EULA differs from the official Burn manifest')
        (output / name).write_bytes(data)
        files[name] = dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                           bundlePath=original, embeddedMember=member)
    (output / 'vc-redist-burn-manifest.xml').write_bytes(manifest)
    (output / 'provenance.json').write_text(json.dumps(dict(
        source='Official VC_redist.x64.exe from the pinned installed MSVC toolchain',
        archiveSha256=archive_sha, archiveBytes=archive.stat().st_size,
        burnManifestSha256=hashlib.sha256(manifest).hexdigest(), files=files,
        redistribution='Application-local CRT DLLs; the redistributable itself is not shipped'
    ), indent=2) + '\n', encoding='utf-8')
    print('Extracted authenticated EN/RU VC runtime terms')


if __name__ == '__main__':
    main()
