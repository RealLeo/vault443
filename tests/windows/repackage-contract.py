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
