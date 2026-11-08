#!/usr/bin/env python3
"""Packaging-only provenance checks; no Windows SDK or compiler is required."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('vault443_repackage', ROOT / 'scripts/windows/repackage.py')
repackage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repackage)
package_spec = importlib.util.spec_from_file_location('vault443_package_finish', ROOT / 'scripts/windows/package.py')
package = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(package)


class RepackageContract(unittest.TestCase):
    def fixture(self, root):
        stage, project = root / 'stage', root / 'project'
        stage.mkdir()
        records = {}
        for name, data in {'vault443d.exe': b'unchanged daemon', 'Qt6Core.dll': b'unchanged patched Qt'}.items():
            path = stage / name
            path.write_bytes(data)
            records[name] = dict(bytes=len(data), sha256=repackage.digest(path))
        (stage / 'build-manifest.json').write_text('original staged manifest')
        installer = root / 'r0.exe'
        installer.write_bytes(b'exact original installer')
        runtime = root / 'r0-source.zip'
        with zipfile.ZipFile(runtime, 'w') as archive:
            archive.writestr('VERSION', '1.3.5\n')
            archive.writestr('packaging/windows/vault443.iss', 'original installer')
        old_source = dict(archive='source.zip', sha256=repackage.digest(runtime))
        manifest = dict(platform='windows', architecture='amd64', productVersion='1.3.5', files=records,
                        source=old_source, nativeToolchain=dict(sourceSha256=old_source['sha256'], qtCoreSha256='original-Qt'),
                        backend=dict(identity='original backend'), dependencyLocks=dict(identity='original locks'))
        baseline = root / 'r0-manifest.json'
        baseline.write_text(json.dumps(manifest))
        for name in ('packaging/windows/vault443.iss', 'packaging/windows/vault443.ico',
                     'scripts/windows/package.py', 'scripts/windows/repackage.py', 'tests/windows/native.ps1'):
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('current ' + name).encode())
        source = root / 'new-source.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('VERSION', '1.3.5\n')
            for path in project.rglob('*'):
                if path.is_file():
                    archive.writestr(path.relative_to(project).as_posix(), path.read_bytes())
        args = SimpleNamespace(stage=stage, output=root / 'output', baseline_installer=installer,
                               baseline_installer_sha256=repackage.digest(installer), baseline_manifest=baseline,
                               baseline_manifest_sha256=repackage.digest(baseline), runtime_source=runtime,
                               source=source, expected_file_count=2)
        return args, project, manifest

    def backend_fixture(self, root):
        args, project, original = self.fixture(root)
        names = ('vault443d.exe', 'vault443-cli.exe', 'vault443-access.exe',
                 'vault443-tunnel.exe', 'vault443-outline.exe')
        backend = dict(productVersion='1.3.5', goVersion='1.27.3', os='windows', architecture='amd64',
                       dependencyPatches={}, binaries={})
        linked = {}
        args.backend_build = root / 'new-backend'
        args.backend_build.mkdir()
        for name in names:
            (args.stage / name).write_bytes(('old ' + name).encode())
            backend['binaries'][name] = repackage.digest(args.stage / name)
            linked[name] = dict(goVersion='go1.27.3', sha256=backend['binaries'][name])
            (args.backend_build / name).write_bytes(('new ' + name).encode())
        (args.stage / 'backend-build.json').write_text(json.dumps(backend))
        components = args.stage / 'licenses/software-components.json'
        components.parent.mkdir()
        components.write_text(json.dumps(dict(linkedGoBinaries=linked, components=[dict(name='unchanged license')])) )
        original['backend'] = backend
        original['files'] = {path.relative_to(args.stage).as_posix(): dict(bytes=path.stat().st_size, sha256=repackage.digest(path))
                             for path in args.stage.rglob('*') if path.is_file() and path.name != 'build-manifest.json'}
        args.baseline_manifest.write_text(json.dumps(original))
        args.baseline_manifest_sha256 = repackage.digest(args.baseline_manifest)
        args.expected_file_count = len(original['files'])
        new_backend = json.loads(json.dumps(backend))
        new_backend['revision'] = 'fixed-backend'
        new_backend['binaries'] = {name: repackage.digest(args.backend_build / name) for name in names}
        (args.backend_build / 'backend-build.json').write_text(json.dumps(new_backend))
        return args, project, original, new_backend

    @staticmethod
    def identity(path):
        return dict(GoVersion='go1.27.3', Path='example/' + path.name,
                    Main=dict(Path='example'), Deps=[dict(Path='licensed-module', Version='v1.0', Sum='h1:original')])

    def test_backend_revision_preserves_native_payload_and_refreshes_actual_license_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            args, project, original, backend = self.backend_fixture(Path(directory))
            original_qt = (args.stage / 'Qt6Core.dll').read_bytes()
            with mock.patch.object(repackage, 'ROOT', project), mock.patch.object(repackage, 'go_binary_identity', side_effect=self.identity), mock.patch.object(repackage.subprocess, 'check_output', return_value=b''):
                revised = repackage.repackage(args)
            self.assertEqual((args.stage / 'Qt6Core.dll').read_bytes(), original_qt)
            self.assertEqual(revised['nativeToolchain'], original['nativeToolchain'])
            self.assertEqual(revised['nativeSource']['sha256'], original['source']['sha256'])
            self.assertEqual(revised['backendSource']['sha256'], repackage.digest(args.source))
            self.assertEqual(revised['backend'], backend)
            self.assertFalse(revised['packagingRevision']['runtimePayloadUnchanged'])
            self.assertTrue(revised['packagingRevision']['nativePayloadUnchanged'])
            components = json.loads((args.stage / 'licenses/software-components.json').read_text())
            self.assertEqual(components['components'], [dict(name='unchanged license')])
            for name, sha in backend['binaries'].items():
                self.assertEqual(repackage.digest(args.stage / name), sha)
                self.assertEqual(components['linkedGoBinaries'][name]['sha256'], sha)
                self.assertEqual(revised['files'][name]['sha256'], sha)

    def test_backend_module_change_rejected_without_stage_or_output_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            args, project, original, _ = self.backend_fixture(Path(directory))
            before = (args.stage / 'build-manifest.json').read_bytes()

            def changed(path):
                result = self.identity(path)
                if path.parent == args.backend_build:
                    result['Deps'].append(dict(Path='unreviewed-module', Version='v2', Sum='h1:new'))
                return result

            with mock.patch.object(repackage, 'ROOT', project), mock.patch.object(repackage, 'go_binary_identity', side_effect=changed), mock.patch.object(repackage.subprocess, 'check_output', return_value=b''):
                with self.assertRaisesRegex(ValueError, 'recollect licenses explicitly'):
                    repackage.repackage(args)
            self.assertEqual((args.stage / 'build-manifest.json').read_bytes(), before)
            self.assertFalse(args.output.exists())
            for name, record in original['files'].items():
                self.assertEqual(repackage.digest(args.stage / name), record['sha256'])

    def test_backend_snapshot_must_include_new_current_go_file(self):
        with tempfile.TemporaryDirectory() as directory:
            args, project, _, _ = self.backend_fixture(Path(directory))
            path = project / 'new.go'
            path.write_text('package main\n')
            with mock.patch.object(repackage, 'ROOT', project), mock.patch.object(repackage.subprocess, 'check_output', return_value=b'new.go\0'):
                with self.assertRaisesRegex(ValueError, 'current Go source: new.go'):
                    repackage.repackage(args)
            self.assertFalse(args.output.exists())

    def test_preserves_runtime_and_records_separate_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            args, project, original = self.fixture(Path(directory))
            with mock.patch.object(repackage, 'ROOT', project):
                revised = repackage.repackage(args)
            self.assertEqual(revised['files'], original['files'])
            self.assertEqual(revised['nativeToolchain'], original['nativeToolchain'])
            self.assertEqual(revised['backend'], original['backend'])
            self.assertEqual(revised['dependencyLocks'], original['dependencyLocks'])
            self.assertEqual(revised['runtimeSource']['sha256'], original['source']['sha256'])
            self.assertEqual(revised['source']['sha256'], repackage.digest(args.source))
            self.assertNotEqual(revised['runtimeSource']['sha256'], revised['source']['sha256'])
            self.assertTrue(revised['packagingRevision']['runtimePayloadUnchanged'])
            self.assertFalse(revised['packagingRevision']['nativeRebuildPerformed'])
            self.assertEqual(repackage.digest(args.output / 'runtime-source-r0.zip'), original['source']['sha256'])
            self.assertEqual(repackage.digest(args.output / 'runtime-build-manifest-r0.json'), args.baseline_manifest_sha256)
            for name, record in original['files'].items():
                self.assertEqual(repackage.digest(args.stage / name), record['sha256'])

    def test_rejects_changed_payload_before_writing_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            args, project, _ = self.fixture(Path(directory))
            path = args.stage / 'Qt6Core.dll'
            data = path.read_bytes()
            path.write_bytes(bytes([data[0] ^ 1]) + data[1:])  # identical size; digest must detect substitution
            before = (args.stage / 'build-manifest.json').read_bytes()
            with mock.patch.object(repackage, 'ROOT', project), self.assertRaisesRegex(ValueError, 'runtime bytes differ'):
                repackage.repackage(args)
            self.assertEqual((args.stage / 'build-manifest.json').read_bytes(), before)
            self.assertFalse(args.output.exists())

    def test_rejects_extra_payload_and_stale_packaging_source(self):
        for failure in ('extra-file', 'stale-source'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                args, project, _ = self.fixture(Path(directory))
                if failure == 'extra-file':
                    (args.stage / 'unexpected.exe').write_bytes(b'not in the original inventory')
                else:
                    (project / 'packaging/windows/vault443.iss').write_text('changed after snapshot')
                before = (args.stage / 'build-manifest.json').read_bytes()
                with mock.patch.object(repackage, 'ROOT', project), self.assertRaises(ValueError):
                    repackage.repackage(args)
                self.assertEqual((args.stage / 'build-manifest.json').read_bytes(), before)
                self.assertFalse(args.output.exists())

    def test_finish_includes_and_verifies_original_runtime_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            args, project, _ = self.fixture(Path(directory))
            with mock.patch.object(repackage, 'ROOT', project):
                revised = repackage.repackage(args)
            (args.output / 'Vault443-1.3.5-windows-x64-setup.exe').write_bytes(b'native installer fixture')
            finish_args = SimpleNamespace(stage=args.stage, source=args.output / 'source.zip', output=args.output)
            with mock.patch.object(package, 'pe_machine', return_value=0x8664):
                package.finish(finish_args)
                artifacts = json.loads((args.output / 'artifact-manifest.json').read_text())['artifacts']
                for name in ('runtime-source-r0.zip', 'runtime-build-manifest-r0.json'):
                    self.assertEqual(artifacts[name]['sha256'], repackage.digest(args.output / name))
                (args.output / 'runtime-source-r0.zip').write_bytes(b'substituted runtime source')
                with self.assertRaisesRegex(ValueError, 'substituted original runtime provenance'):
                    package.finish(finish_args)


if __name__ == '__main__':
    unittest.main()
