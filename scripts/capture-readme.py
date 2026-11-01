#!/usr/bin/env python3
"""Capture the English product gallery using demo-only temporary preferences.

Source scripts/qt-env.sh first when using the local Qt development runtime.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'docs/images/readme'

def main():
    manifest = json.loads((DEST / 'manifest.json').read_text())
    manifest['version'] = (ROOT / 'VERSION').read_text().strip()
    manifest['screens'] = list({entry['file']: entry for entry in manifest['screens']}.values())
    manifest['capture']['command'] = 'LANGUAGE=en QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software build/vault443 --demo --demo-state <demoState> --demo-screen <demoScreen> --screenshot docs/images/readme/<file> (temporary XDG_CONFIG_HOME)'
    with tempfile.TemporaryDirectory(prefix='vault443-gallery-') as temporary:
        env = dict(os.environ, XDG_CONFIG_HOME=temporary, LANGUAGE='en',
                   QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software')
        for entry in manifest['screens']:
            image = DEST / entry['file']
            result = subprocess.run([str(ROOT / 'build/vault443'), '--demo',
                                     '--demo-state', entry['demoState'], '--demo-screen', entry['demoScreen'],
                                     '--screenshot', str(image)], env=env, capture_output=True, timeout=15)
            if result.returncode or any(error in result.stderr for error in [b'ReferenceError', b'TypeError']):
                raise SystemExit(result.stderr.decode())
            entry['sha256'] = hashlib.sha256(image.read_bytes()).hexdigest()
    (DEST / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

if __name__ == '__main__':
    main()
