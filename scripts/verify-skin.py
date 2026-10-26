#!/usr/bin/env python3
"""Compare extracted artwork and actual Qt screenshot to the approved original."""
import argparse
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('screenshot', type=Path, help='Fresh demo screenshot at --scale 1.0 (944×960)')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'assets/skin/manifest.json').read_text())
source = root / 'design/reference/concept.png'
assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest['referenceSHA256']
x, y, width, height = manifest['windowRect']
original = Image.open(source).convert('RGB').crop((x, y, x+width, y+height))
extracted = Image.open(root / 'assets/skin/window.png').convert('RGB')
assert original.size == extracted.size
mask = Image.new('L', original.size, 255)
draw = ImageDraw.Draw(mask)
for left, top, right, bottom in manifest['repairRects']:
    draw.rectangle((left-x, top-y, right-x-1, bottom-y-1), fill=0)
retained = sum(bool(v) for v in mask.getdata())
different = sum(bool(m) and any(p) for p, m in zip(ImageChops.difference(original, extracted).getdata(), mask.getdata()))
assert different == 0, f'{different} pixels outside recorded repairs changed'
print(f'Original artwork: {retained} retained pixels, zero differences outside repairs')

# These regions have no live text or state; compare the real 1:1 Qt rendering.
# This deliberately makes no claim about generated lettering or retouched areas.
screenshot = Image.open(args.screenshot).convert('RGB')
assert screenshot.size == original.size
regions = {
    'title bar': (0, 0, 944, 84),
    'left rail': (0, 84, 40, 845),
    'right rail': (912, 84, 944, 845),
    'divider': (20, 747, 924, 760),
    'bottom edge': (0, 930, 944, 960),
}
for name, box in regions.items():
    diff = ImageChops.difference(extracted.crop(box), screenshot.crop(box))
    assert not diff.getbbox(), f'{name} differs from the reference'
    print(f'Qt screenshot {name}: {diff.width * diff.height} pixels match exactly')
