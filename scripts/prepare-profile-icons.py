#!/usr/bin/env python3
"""Prepare generated raster layers for Qt; never regenerate or paint artwork."""
import json
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "design/profile-icons"
OUTPUT = ROOT / "assets/profile-icons"
catalog = json.loads((OUTPUT / "catalog.json").read_text())
for entry in catalog["icons"]:
    if entry["kind"] != "transparent-emblem":
        continue
    image = Image.open(SOURCE / entry["file"])
    assert image.mode == "RGBA" and image.getchannel("A").getextrema() == (0, 255), entry["id"]
    image.resize((256, 256), Image.Resampling.LANCZOS).save(OUTPUT / entry["file"], optimize=True)

blank = Image.open(SOURCE / "blank-generated.png").resize((114, 115), Image.Resampling.LANCZOS)
frame = Image.open(ROOT / "assets/skin/emblem-antenna.png").convert("RGBA")
frame.paste(blank.crop((17, 18, 99, 100)), (17, 18))
frame.save(OUTPUT / "blank.png")
print("Prepared 20 transparent emblems and the blank original frame")
