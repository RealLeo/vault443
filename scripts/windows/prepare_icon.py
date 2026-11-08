#!/usr/bin/env python3
"""Derive the Windows ICO from the existing emblem; requires Pillow 10.2.0.

The ICO is committed, so normal native builds do not need Pillow. Run this
script when the source emblem changes and review its resulting hash.
"""
import hashlib
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assets/profile-icons/vault-door.png'
OUTPUT = ROOT / 'packaging/windows/vault443.ico'
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def main():
    with Image.open(SOURCE) as source:
        image = source.convert('RGBA')
        if image.size != (256, 256):
            raise SystemExit('Expected the existing 256px application emblem')
        image.save(OUTPUT, format='ICO', sizes=[(size, size) for size in SIZES])
    with Image.open(OUTPUT) as icon:
        if icon.ico.sizes() != {(size, size) for size in SIZES}:
            raise SystemExit('Incomplete Windows icon size set')
        if icon.ico.getimage((256, 256)).convert('RGBA').tobytes() != image.tobytes():
            raise SystemExit('The full-size icon differs from the original emblem')
    print(OUTPUT.relative_to(ROOT), hashlib.sha256(OUTPUT.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
