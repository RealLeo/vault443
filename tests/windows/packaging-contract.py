#!/usr/bin/env python3
"""Host-only packaging regression checks; no SDK, VM or network is used."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/windows' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class PackagingContract(unittest.TestCase):
    def test_stage_copies_only_production_go_executables(self):
        build = module('vault443_windows_build', 'build.py')
        expected = {'vault443d.exe', 'vault443-cli.exe', 'vault443-access.exe',
                    'vault443-tunnel.exe', 'vault443-outline.exe'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in expected | {'worknet-windows.test.exe', 'diagnostic.exe'}:
                path = root / 'build-windows' / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(name.encode())
            for name in ('LICENSE', 'VERSION', 'scripts/windows/provision.ps1', 'scripts/windows/extract_sources.py'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            sdk = root / 'sdk'
            (sdk / 'media').mkdir(parents=True)
            for name, entries in {
                'xray-windows-x64.zip': {'xray.exe': 'xray', 'LICENSE': 'xray license'},
                'wintun-0.14.1.zip': {'wintun/bin/amd64/wintun.dll': 'wintun', 'wintun/LICENSE.txt': 'license'},
            }.items():
                with zipfile.ZipFile(sdk / 'media' / name, 'w') as archive:
                    for entry, data in entries.items():
                        archive.writestr(entry, data)
            (sdk / 'openvpn').mkdir()
            (sdk / 'openvpn/openvpn.exe').write_bytes(b'openvpn')
            stage = root / 'stage'
            with mock.patch.object(build, 'ROOT', root), mock.patch.object(build.subprocess, 'check_output', return_value=b'VERSION\0'), mock.patch.dict(os.environ, {'SOURCE_DATE_EPOCH': '1600000000'}):
                build.stage(stage, sdk)
            actual = {path.name for path in (stage / 'app').glob('*.exe')}
            self.assertEqual(actual, expected | {'xray.exe'})
            for name in expected:
                self.assertEqual((stage / 'app' / name).read_bytes(), name.encode())

    def test_validator_rejects_test_pe_including_nested_case_variants(self):
        package = module('vault443_windows_package', 'package.py')
        for name in ('worknet-windows.test.exe', 'openvpn/WORKNET.TEST.EXE'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                stage = Path(directory)
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'QA executable')
                with self.assertRaisesRegex(ValueError, 'Test executable'):
                    list(package.stage_files(stage))

    def test_licenses_accept_only_the_reviewed_wf_replacement(self):
        licenses = module('vault443_windows_licenses', 'licenses.py')
        patch = licenses.wf_patch
        output = 'test.exe: go1.27.3\n\tdep\t' + patch.MODULE + '\t' + patch.VERSION + '\n\t=>\t' + patch.REPLACEMENT + '\t(devel)\t\n'
        with mock.patch.object(licenses.subprocess, 'check_output', return_value=output):
            _, dependencies, replacements = licenses.binary_modules(None, {}, Path('test.exe'))
        self.assertEqual(dependencies, [(patch.MODULE, patch.VERSION, patch.SUM)])
        self.assertEqual(replacements, {patch.MODULE})
        for bad in (output.replace(patch.MODULE, 'example.invalid/foreign'),
                    output.replace(patch.VERSION, 'v0.0.0-unknown'),
                    output.replace(patch.REPLACEMENT, './unreviewed'),
                    output.replace('(devel)', 'v9.9.9')):
            with self.subTest(output=bad), mock.patch.object(licenses.subprocess, 'check_output', return_value=bad):
                with self.assertRaisesRegex(ValueError, 'explicit licensing review'):
                    licenses.binary_modules(None, {}, Path('test.exe'))

    def test_reviewed_fork_rejects_source_drift(self):
        licenses = module('vault443_windows_licenses_verify', 'licenses.py')
        patch = licenses.wf_patch
        patch.verify(ROOT)
        drift = patch.source_files(ROOT / 'third_party/wf')
        drift['types.go'] = '0' * 64
        with mock.patch.object(patch, 'source_files', return_value=drift):
            with self.assertRaisesRegex(ValueError, 'source tree differs'):
                patch.verify(ROOT)


if __name__ == '__main__':
    unittest.main()
