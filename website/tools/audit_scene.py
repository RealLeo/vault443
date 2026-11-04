#!/usr/bin/env python3
"""Visual QA only (Pillow): source invariants and matched-codec screenshot diffs."""
from io import BytesIO
import json
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageStat, JpegImagePlugin

ROOT = Path(__file__).resolve().parents[2]
QA = ROOT / "test-results/website-exact-scene"


def rectangle(draw, box, padding=0, fill=255):
    x, y, w, h = box
    draw.rectangle((x-padding, y-padding, x+w+padding-1, y+h+padding-1), fill=fill)


def main():
    layout = json.loads((ROOT / "website/data/scene-layout.json").read_text())
    manifest = json.loads((ROOT / "design/landing/vault-door/atlas/manifest.json").read_text())
    report = {"captureNote": "Browser screenshot API emits JPEG. Compare to atlas re-encoded with identical quantization tables and subsampling; native preview and localized text are separately excluded.", "comparisons": []}
    for item in manifest["assets"]:
        mode, lang = item["mode"], item["lang"]
        source = Image.open(ROOT / item["reference"]).convert("RGB")
        master = Image.open(ROOT / item["master"]).convert("RGB")
        allowed = Image.new("L", source.size)
        draw = ImageDraw.Draw(allowed)
        for box in item["repairs"].values():
            rectangle(draw, box)
        protected = ImageChops.invert(allowed)
        source_diff = ImageChops.difference(source, master)
        source_error = ImageStat.Stat(source_diff, protected).sum
        assert source_error == [0, 0, 0], "Original pixels changed outside text repairs"
        screenshot = Image.open(QA / f"{lang}-{mode}-reference.jpg")
        assert screenshot.size == source.size
        atlas = Image.open(ROOT / item["production"]).convert("RGB")
        # Isolate layout/material differences from the browser's JPEG transport.
        encoded = BytesIO()
        atlas.save(encoded, "JPEG", qtables=screenshot.quantization, subsampling=JpegImagePlugin.get_sampling(screenshot))
        expected = Image.open(BytesIO(encoded.getvalue())).convert("RGB")
        actual = screenshot.convert("RGB")
        exceptions = Image.new("L", source.size)
        draw = ImageDraw.Draw(exceptions)
        rectangle(draw, layout[mode]["slots"]["vault-window"], 8)
        if lang == "ru":
            for name, box in item["repairs"].items():
                if name != "brand":
                    rectangle(draw, box, 10)
        elif mode == "desktop":
            rectangle(draw, item["repairs"]["statusCaption"], 8)
        texture_mask = ImageChops.invert(exceptions)
        difference = ImageChops.difference(actual, expected)
        error = ImageStat.Stat(difference, texture_mask).mean
        Image.blend(expected, actual, .5).save(QA / f"{lang}-{mode}-overlay.png")
        heat = ImageEnhance.Brightness(difference).enhance(5)
        heat.save(QA / f"{lang}-{mode}-difference.png")
        report["comparisons"].append({"lang": lang, "mode": mode,
            "sourcePixelsChangedOutsideTextRepairs": 0,
            "textureMeanAbsoluteRGBError": [round(v, 4) for v in error],
            "textureErrorThreshold": 2.5, "passes": max(error) <= 2.5,
            "exceptions": "Native app preview; localized captions; edited status caption"})
    responsive = json.loads((QA / "responsive.json").read_text())
    report["maxGeometryErrorCSSPx"] = max(item["geometryError"] for item in responsive)
    report["responsiveCases"] = len(responsive)
    report["responsivePasses"] = all(not item["overflow"] and not item["textOverflow"] and not [url for url in item["failedImages"] if url] and item["geometryError"] <= 1 for item in responsive)
    (QA / "visual-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    assert all(item["passes"] for item in report["comparisons"]), "Texture mismatch outside permitted regions"
    assert report["responsivePasses"]


if __name__ == "__main__":
    main()
