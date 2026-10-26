#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

root = Path(__file__).resolve().parents[1]
lock = json.loads((root/'packaging/xray-lock.json').read_text())
for arch in sys.argv[1:] or ['amd64', 'arm64']:
    asset = lock['assets'][arch]
    folder = root / '.cache/xray' / arch
    folder.mkdir(parents=True,exist_ok=True)
    archive = folder / asset['file']
    if not archive.exists():
        url = f"https://github.com/XTLS/Xray-core/releases/download/{lock['tag']}/{asset['file']}"
        with urllib.request.urlopen(url,timeout=120) as response:
            archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != asset['sha256']:
        raise SystemExit('Invalid Xray SHA256: '+str(archive))
    with zipfile.ZipFile(archive) as z:
        (folder/'xray').write_bytes(z.read('xray'))
        (folder/'xray').chmod(0o755)
        for name in ['LICENSE', 'README.md']:
            if name in z.namelist(): (folder/name).write_bytes(z.read(name))
    print(arch, lock['version'], 'SHA256 verified')
