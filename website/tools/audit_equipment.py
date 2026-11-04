#!/usr/bin/env python3
"""Authoring QA: protected source pixels, periodic material and browser overlays.

Pillow is required only for this offline visual audit, never for Pages builds.
"""
from io import BytesIO
import json
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageStat, JpegImagePlugin

ROOT = Path(__file__).resolve().parents[2]
QA = ROOT / "test-results/website-equipment"


def rectangles(size, boxes, padding=0):
    mask = Image.new("L", size)
    draw = ImageDraw.Draw(mask)
    for x, y, w, h in boxes:
        draw.rectangle((x-padding, y-padding, x+w+padding-1, y+h+padding-1), fill=255)
    return mask


def main():
    manifest = json.loads((ROOT / "design/landing/equipment/manifest.json").read_text())
    report = {"comparisons": [], "captureNote": "1536x1024 CUA captures. Compare the WebP atlas after matching the browser JPEG quantization/subsampling. Native lettering, actual screenshots and changing relay states are explicit exceptions; source hardware outside recorded repairs is protected."}
    # These are live states/HTML added on top of the recorded text repairs.
    extra = {
        "routing": [[218, 480, 135, 32], [430, 670, 140, 45], [808, 203, 44, 44], [1152, 203, 44, 44]] +
                   [[930, 326+y, 80, 92] for y in (0,160,320)] +
                   [[1030, 341+y, 50, 65] for y in (0,160,320)],
        "gallery": [[675,220,550,550]],
        "downloads": [[704,236+y,39,39] for y in (0,160,320,480)],
    }
    for kind, asset in zip(("routing", "gallery", "downloads"), manifest["assets"]):
        source = Image.open(ROOT / asset["reference"]).convert("RGB")
        master = Image.open(ROOT / asset["master"]).convert("RGB")
        protected = ImageChops.invert(rectangles(source.size, asset["repairs"]))
        assert ImageStat.Stat(ImageChops.difference(source, master), protected).sum == [0,0,0]
        atlas = Image.open(ROOT / asset["production"]).convert("RGB")
        for lang in ("en", "ru"):
            capture = Image.open(QA / f"{lang}-{kind}-reference.jpg")
            assert capture.size == source.size == (1536,1024)
            actual = capture.convert("RGB")
            encoded = BytesIO()
            atlas.save(encoded, "JPEG", qtables=capture.quantization, subsampling=JpegImagePlugin.get_sampling(capture))
            expected = Image.open(BytesIO(encoded.getvalue())).convert("RGB")
            texture = ImageChops.invert(rectangles(source.size, asset["repairs"]+extra[kind], 12))
            difference = ImageChops.difference(expected, actual)
            error = ImageStat.Stat(difference, texture).mean
            Image.blend(source, actual, .5).save(QA / f"{lang}-{kind}-concept-overlay.png")
            Image.blend(expected, actual, .5).save(QA / f"{lang}-{kind}-production-overlay.png")
            ImageEnhance.Brightness(difference).enhance(5).save(QA / f"{lang}-{kind}-difference.png")
            texture.save(QA / f"{lang}-{kind}-texture-mask.png")
            report["comparisons"].append({"lang":lang,"section":kind,"sourcePixelsChangedOutsideRepairs":0,"textureMeanAbsoluteRGBError":[round(v,4) for v in error],"threshold":2.5,"passes":max(error)<=2.5})
    tile = Image.open(ROOT / manifest["texture"]["production"]).convert("RGB")
    w,h = tile.size
    horizontal = ImageChops.difference(tile.crop((0,0,1,h)), tile.crop((w-1,0,w,h))).getbbox()
    vertical = ImageChops.difference(tile.crop((0,0,w,1)), tile.crop((0,h-1,w,h))).getbbox()
    assert horizontal is None and vertical is None
    repeat = Image.new("RGB", (w*3,h*3))
    for y in range(3):
        for x in range(3):
            repeat.paste(tile,(x*w,y*h))
    repeat.save(QA / "steel-3x3.png")
    responsive = json.loads((QA / "responsive.json").read_text())
    report.update(textureOppositeEdgeError=0, responsiveCases=len(responsive),
                  maxGeometryErrorCSSPx=max(item["geometryError"] for item in responsive),
                  responsivePasses=all(not item["overflow"] and not item["textOverflow"] and not item["failedImages"] and item["geometryError"]<=1 for item in responsive),
                  geometryException="Two intentionally visually-hidden desktop support notes; their full text remains below the installer bay.")
    (QA / "visual-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    assert all(item["passes"] for item in report["comparisons"])
    assert report["responsivePasses"]


if __name__ == "__main__":
    main()
