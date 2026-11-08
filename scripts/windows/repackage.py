#!/usr/bin/env python3
"""Verify a restored runtime and prepare an honest packaging-only revision.

No compiler, SDK, Go command or network is used. Pass the original installer and
build manifest with independently recorded hashes, its original runtime source
ZIP, and a fresh source snapshot containing the current installer and QA files.
Only build-manifest.json is changed inside the verified runtime stage.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pinned(path, expected):
    if not re.fullmatch('[a-f0-9]{64}', expected) or digest(path) != expected:
        raise ValueError('Pinned input differs: ' + str(path))


def source_inputs():
    files = {ROOT / name for name in (
        'packaging/windows/vault443.iss', 'packaging/windows/vault443.ico',
        'scripts/windows/package.py', 'scripts/windows/repackage.py')}
    for pattern in ('*.ps1', '*.py'):
        files.update((ROOT / 'tests/windows').rglob(pattern))
    return sorted(files)


def verify_source(source, version):
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Source ZIP contains duplicate entries')
        if archive.read('VERSION').decode('utf-8-sig').strip() != version:
            raise ValueError('Source ZIP product version differs')
        for path in source_inputs():
            name = path.relative_to(ROOT).as_posix()
            if path.is_symlink() or not path.is_file() or archive.read(name) != path.read_bytes():
                raise ValueError('Source ZIP does not contain the current packaging/QA input: ' + name)


def verify_runtime(stage, records, expected_count):
    if len(records) != expected_count:
        raise ValueError(f'Expected {expected_count} original runtime records, got {len(records)}')
    actual = {}
    for path in stage.rglob('*'):
        if path.is_symlink():
            raise ValueError('Runtime contains a symlink: ' + str(path))
        if path.is_file() and path.relative_to(stage).as_posix() != 'build-manifest.json':
            actual[path.relative_to(stage).as_posix()] = path
    if set(actual) != set(records):
        raise ValueError('Restored runtime file set differs: missing=' + str(sorted(set(records) - set(actual))) +
                         ', extra=' + str(sorted(set(actual) - set(records))))
    for name, record in records.items():
        path = actual[name]
        if path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
            raise ValueError('Restored runtime bytes differ: ' + name)


def preserve(source, target):
    if source.resolve() == target.resolve():
        return
    if target.exists():
        if digest(target) != digest(source):
            raise ValueError('Refusing to overwrite different provenance: ' + str(target))
        return
    shutil.copyfile(source, target)


def repackage(args):
    stage, output = args.stage.resolve(), args.output.resolve()
    pinned(args.baseline_installer, args.baseline_installer_sha256)
    pinned(args.baseline_manifest, args.baseline_manifest_sha256)
    baseline = json.loads(args.baseline_manifest.read_text(encoding='utf-8-sig'))
    if baseline.get('platform') != 'windows' or baseline.get('architecture') != 'amd64':
        raise ValueError('Expected an original Windows amd64 build manifest')
    pinned(args.runtime_source, baseline['source']['sha256'])
    if baseline['nativeToolchain']['sourceSha256'] != baseline['source']['sha256']:
        raise ValueError('Original native toolchain source identity differs')
    verify_source(args.source, baseline['productVersion'])
    verify_runtime(stage, baseline['files'], args.expected_file_count)
    source_sha = digest(args.source)
    runtime_name, manifest_name = 'runtime-source-r0.zip', 'runtime-build-manifest-r0.json'
    manifest = copy.deepcopy(baseline)
    manifest['runtimeSource'] = dict(baseline['source'], archive=runtime_name)
    manifest['source'] = dict(archive='source.zip', sha256=source_sha)
    manifest['packagingRevision'] = dict(
        schemaVersion=1, kind='packaging-only', baselineInstallerSha256=args.baseline_installer_sha256,
        baselineManifestSha256=args.baseline_manifest_sha256,
        installerScriptSha256=digest(ROOT / 'packaging/windows/vault443.iss'),
        installerIconSha256=digest(ROOT / 'packaging/windows/vault443.ico'),
        newSourceSha256=source_sha, runtimePayloadUnchanged=True,
        runtimeFileCount=len(baseline['files']), nativeRebuildPerformed=False,
        runtimeBuildManifest=dict(archive=manifest_name, sha256=args.baseline_manifest_sha256),
    )
    # Every byte check precedes the first write. The original native toolchain,
    # backend, dependency locks and runtime file inventory remain untouched.
    output.mkdir(parents=True, exist_ok=True)
    preserve(args.runtime_source, output / runtime_name)
    preserve(args.baseline_manifest, output / manifest_name)
    preserve(args.source, output / 'source.zip')
    encoded = json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'
    temporary = stage / 'build-manifest.json.repackage-tmp'
    temporary.write_text(encoded, encoding='utf-8')
    temporary.replace(stage / 'build-manifest.json')
    (output / 'build-manifest.json').write_text(encoded, encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stage', 'output', 'baseline-installer', 'baseline-manifest', 'runtime-source', 'source'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('baseline-installer-sha256', 'baseline-manifest-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--expected-file-count', type=int, default=1763)
    args = parser.parse_args()
    try:
        manifest = repackage(args)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error))
    print(json.dumps(dict(runtimeFilesVerified=len(manifest['files']), runtimePayloadUnchanged=True,
                         buildManifestSha256=digest(args.stage / 'build-manifest.json'),
                         packagingRevision=manifest['packagingRevision']), indent=2))


if __name__ == '__main__':
    main()
