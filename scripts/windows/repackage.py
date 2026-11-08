#!/usr/bin/env python3
"""Verify a restored runtime and prepare a packaging or Go-backend revision.

No compiler, SDK, Go command or network is used. Pass the original installer and
build manifest with independently recorded hashes, its original runtime source
ZIP, and a fresh source snapshot containing the current installer and QA files.
By default only build-manifest.json changes. --backend-build replaces the five
project Go binaries after verifying unchanged compiler/module/license identities;
the original GUI, Qt and native-toolchain provenance are preserved.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
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


def go_binary_identity(path):
    """Inspect BuildInfo with the pinned Go tool, without building any code."""
    spec = importlib.util.spec_from_file_location('vault443_repackage_toolchain', ROOT / 'scripts/toolchain.py')
    toolchain = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(toolchain)
    go, env = toolchain.ensure(offline=True)
    info = json.loads(subprocess.check_output([str(go), 'version', '-m', '-json', str(path)], env=env, text=True))
    settings = {item['Key']: item['Value'] for item in info.get('Settings', [])}
    if any(settings.get(key) != value for key, value in {'GOOS': 'windows', 'GOARCH': 'amd64', 'CGO_ENABLED': '0'}.items()):
        raise ValueError('Replacement is not a Windows amd64 CGO-disabled Go executable: ' + path.name)
    return {key: info.get(key) for key in ('GoVersion', 'Path', 'Main', 'Deps')}


def backend_revision(directory, stage, baseline):
    """Reuse notices only when the actual linked compiler/modules are identical."""
    backend = json.loads((directory / 'backend-build.json').read_text(encoding='utf-8-sig'))
    original = baseline['backend']
    expected = {'vault443d.exe', 'vault443-cli.exe', 'vault443-access.exe',
                'vault443-tunnel.exe', 'vault443-outline.exe'}
    if set(backend.get('binaries', {})) != expected or set(original['binaries']) != expected:
        raise ValueError('A backend revision requires exactly the five original project Go executables')
    for key in ('productVersion', 'goVersion', 'os', 'architecture', 'dependencyPatches'):
        if backend.get(key) != original.get(key):
            raise ValueError('Backend compiler/platform/dependency provenance changed: ' + key)
    components_path = stage / 'licenses/software-components.json'
    components = json.loads(components_path.read_text(encoding='utf-8-sig'))
    replacements = {}
    for name in sorted(expected):
        path = directory / name
        pinned(path, backend['binaries'][name])
        old_identity = go_binary_identity(stage / name)
        new_identity = go_binary_identity(path)
        if old_identity != new_identity:
            raise ValueError('Go compiler/module identity changed; recollect licenses explicitly: ' + name)
        linked = components['linkedGoBinaries'][name]
        if linked['sha256'] != baseline['files'][name]['sha256'] or linked['goVersion'] != new_identity['GoVersion']:
            raise ValueError('Original collected Go license identity differs: ' + name)
        if new_identity['GoVersion'] != 'go' + backend['goVersion']:
            raise ValueError('Actual Go compiler differs from the backend build manifest: ' + name)
        linked['sha256'] = digest(path)
        replacements[name] = path.read_bytes()
    replacements['backend-build.json'] = (directory / 'backend-build.json').read_bytes()
    replacements['licenses/software-components.json'] = (json.dumps(components, ensure_ascii=False, indent=2) + '\n').encode()
    return backend, replacements


def verify_backend_source(source):
    # A packaging snapshot may otherwise contain an old Go implementation while
    # the replacement binary was built from current sources. Native GUI sources
    # remain separately attributed to the original R0 archive/toolchain.
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                                    cwd=ROOT).decode().split('\0')
    required = {name for name in names if name and not name.startswith(('website/', 'design/', '.agents/'))
                and (name.endswith('.go') or Path(name).name in ('go.mod', 'go.sum'))}
    with zipfile.ZipFile(source) as archive:
        for name in sorted(required):
            path = ROOT / name
            if name not in archive.namelist() or path.is_symlink() or not path.is_file() or archive.read(name) != path.read_bytes():
                raise ValueError('Backend source snapshot differs from the current Go source: ' + name)


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
    replacements = {}
    if getattr(args, 'backend_build', None) is not None:
        verify_backend_source(args.source)
        backend, replacements = backend_revision(args.backend_build.resolve(), stage, baseline)
        manifest['backend'] = backend
        manifest['backendSource'] = copy.deepcopy(manifest['source'])
        manifest['nativeSource'] = copy.deepcopy(manifest['runtimeSource'])
        manifest['runtimeSource']['scope'] = 'Original R0 runtime; project Go applications are superseded by backendSource'
        changed = []
        for name, data in replacements.items():
            record = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            if record != manifest['files'][name]:
                changed.append(name)
            manifest['files'][name] = record
        manifest['packagingRevision'].update(
            kind='backend-and-packaging', runtimePayloadUnchanged=False, nativePayloadUnchanged=True,
            backendRebuildPerformed=True, backendBuildManifestSha256=digest(args.backend_build / 'backend-build.json'),
            changedRuntimeFiles=sorted(changed),
            licenseRefresh='Actual Go compiler/module identities reverified unchanged; linked binary hashes refreshed',
        )
    # Every byte check precedes the first write. The original native toolchain,
    # backend, dependency locks and runtime file inventory remain untouched.
    output.mkdir(parents=True, exist_ok=True)
    preserve(args.runtime_source, output / runtime_name)
    preserve(args.baseline_manifest, output / manifest_name)
    preserve(args.source, output / 'source.zip')
    for name, data in replacements.items():
        target = stage / name
        temporary = target.with_name(target.name + '.backend-revision-tmp')
        temporary.write_bytes(data)
        temporary.replace(target)  # preserve any hardlinked original R0 snapshot
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
    parser.add_argument('--backend-build', type=Path,
                        help='Optional final build-windows directory; reuse original GUI/Qt and refresh project Go executables')
    args = parser.parse_args()
    try:
        manifest = repackage(args)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
    print(json.dumps(dict(runtimeFilesVerified=len(manifest['files']),
                         runtimePayloadUnchanged=manifest['packagingRevision']['runtimePayloadUnchanged'],
                         buildManifestSha256=digest(args.stage / 'build-manifest.json'),
                         packagingRevision=manifest['packagingRevision']), indent=2))


if __name__ == '__main__':
    main()
