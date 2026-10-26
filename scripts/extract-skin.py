#!/usr/bin/env python3
"""Deterministically slice the approved art, using imagegen only under removed text."""
from pathlib import Path
import json
import hashlib
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parents[1]
original = Image.open(root / 'design/reference/concept.png').convert('RGBA')
plate = Image.open(root / 'design/reference/clean-plate.png').convert('RGBA')
assert original.size == plate.size == (1536, 1024)
out = root / 'assets/skin'
out.mkdir(parents=True, exist_ok=True)
# Only these interiors may differ from the approved original. Frame pixels remain exact.
repairs = [(442,138,565,177),
 (551,249,826,294),(625,307,858,348),
 (551,435,844,480),(625,499,858,544),
 (551,624,844,672),(625,689,858,735),
 (945,281,1154,326),(945,472,1154,518),(945,662,1154,709),
 (458,810,651,853),(784,810,910,853),(1032,810,1162,853),
 (468,912,709,958),(910,912,1158,958),
 (402,915,444,953),(844,915,885,953)]
clean = original.copy()
for box in repairs:
    clean.paste(plate.crop(box), box[:2])

# Vault 443 branding: only paste the generated nameplate interior and blank CRT
# interior. Everything outside these rectangles remains the approved source.
branding_path = root / 'design/branding/vault443-generated.png'
branding = Image.open(branding_path).convert('RGBA').resize((944, 960), Image.Resampling.LANCZOS)
branding_repairs = [(214, 18, 726, 68), (70, 772, 878, 828)]
for left, top, right, bottom in branding_repairs:
    clean.paste(branding.crop((left, top, right, bottom)), (left+296, top+32))
    repairs.append((left+296, top+32, right+296, bottom+32))

boxes = {
    'window': (296, 32, 1240, 992),
    'card-1': (336, 214, 1208, 396),
    'card-2': (336, 399, 1208, 585),
    'card-3': (336, 589, 1208, 779),
    'button-red': (924, 257, 1171, 345),
    'button-green': (924, 447, 1171, 536),
    'led-on': (557, 302, 611, 355),
    'led-off': (557, 492, 611, 545),
    'emblem-antenna': (380, 245, 494, 360),
    'emblem-dish': (380, 434, 495, 548),
    'emblem-globe': (380, 625, 495, 741),
    'stats': (352, 792, 1182, 866),
    'checkbox-off': (396, 908, 448, 958),
    'checkbox-on': (396, 908, 448, 958),
}

manifest = {'version':2,'referenceSize':[1536,1024],'windowRect':[296,32,944,960],
 'brandingSource':'design/branding/vault443-generated.png',
 'brandingSHA256':hashlib.sha256(branding_path.read_bytes()).hexdigest(),
 'defaultScale':0.5,'referenceSHA256':hashlib.sha256((root/'design/reference/concept.png').read_bytes()).hexdigest(),
 'repairRects':[list(b) for b in repairs], 'assets':{},
 'palette':{'phosphor':'#78df8a','gold':'#e7c68a','muted':'#708985','crt':'#070f08'},
 'layout':{'cardRects':[[40,182,872,182],[40,367,872,186],[40,557,872,190]],
   'profileNameX':263,'profileNameY':[217,403,592],
   'statusX':335,'statusY':[275,467,657],
   'buttonRects':[[628,225,247,88],[628,415,247,89],[628,605,247,89]],
   'ledRects':[[261,270,54,53],[261,460,54,53],[261,650,54,53]]}}
for name,box in boxes.items():
    source = original if name == 'checkbox-on' else clean
    piece = source.crop(box)
    piece.save(out / (name+'.png'))
    manifest['assets'][name]={'file':name+'.png','sourceRect':list(box),
        'position':[box[0]-296,box[1]-32], 'size':list(piece.size),
        'border':[14,14,14,14] if name.startswith('button-') or name.startswith('card-') else [0,0,0,0]}
# This is an inspection artifact, not application UI.
contact = Image.new('RGB',(1200,((len(boxes)+3)//4)*157+20),'#131712')
draw=ImageDraw.Draw(contact)
for i,(name,box) in enumerate(boxes.items()):
    piece=Image.open(out/(name+'.png')).convert('RGBA')
    piece.thumbnail((275,137))
    x=(i%4)*300+12; y=(i//4)*157+20
    contact.paste(piece,(x,y),piece)
    draw.text((x,y-16),name,fill='#e7c68a')
preview_dir = root / 'test-results/artwork'
preview_dir.mkdir(parents=True, exist_ok=True)
contact.save(preview_dir / 'asset-contact-sheet.png')
(out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
print(f'Wrote {len(boxes)} assets; retained original pixels outside {len(repairs)} repair rectangles.')
