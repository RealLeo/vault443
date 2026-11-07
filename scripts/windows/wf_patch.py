"""Verify the sole reviewed local Windows module replacement and its sources."""
import hashlib
import json
from pathlib import Path

MODULE = 'github.com/tailscale/wf'
VERSION = 'v0.0.0-20240214030419-6fbb0a674ee6'
SUM = 'h1:l10Gi6w9jxvinoiq15g8OToDdASBni4CyJOdHY1Hr8M='
REPLACEMENT = './third_party/wf'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlink in reviewed wf source')
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = digest(path)
    return result


def tree_hash(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify(root):
    root = Path(root)
    path = root / 'packaging/windows/wf-patch.json'
    record = json.loads(path.read_text())
    if (record['module'], record['upstreamVersion'], record['upstreamModuleSum'], record['replacement']) != (MODULE, VERSION, SUM, REPLACEMENT):
        raise ValueError('Unreviewed local wf dependency identity')
    files = source_files(root / 'third_party/wf')
    if files != record['patchedFiles'] or tree_hash(files) != record['patchedSourceTreeSha256']:
        raise ValueError('Reviewed wf source tree differs from patch manifest')
    if digest(root / record['patchFile']) != record['patchSha256']:
        raise ValueError('Reviewed wf patch differs from patch manifest')
    upstream = record['upstreamFiles']
    if tree_hash(upstream) != record['upstreamSourceTreeSha256']:
        raise ValueError('Invalid upstream wf source identity')
    changes = {name for name in set(upstream) | set(files) if upstream.get(name) != files.get(name)}
    if changes != {'types.go', 'malloc.go', 'vault443_abi_windows_test.go'}:
        raise ValueError('wf fork changes exceed the reviewed ABI/alignment patch and tests')
    if f'{MODULE} {VERSION} {SUM}' not in (root / 'go.sum').read_text().splitlines():
        raise ValueError('Upstream wf h1 is absent from root go.sum')
    return dict(record, manifestFile='packaging/windows/wf-patch.json', manifestSha256=digest(path))
