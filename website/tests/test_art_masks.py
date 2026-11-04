"""Authoring regression: overlapping repairs must never restore old lettering."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow is an optional authoring dependency")
class RepairMaskTests(unittest.TestCase):
    def test_overlapping_repairs_preserve_the_cleaned_interior(self):
        for filename, name in (("prepare_equipment.py", "mask"), ("prepare_scene.py", "repair_mask")):
            spec = importlib.util.spec_from_file_location(filename[:-3], ROOT / "tools" / filename)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            result = getattr(module, name)((100,100), [(10,10,60,60),(30,30,60,60)])
            with self.subTest(recipe=filename):
                self.assertEqual(result.getpixel((32,31)), 255, "The feathered edge of a later repair must not erase an earlier interior")
                self.assertEqual(result.getpixel((50,50)), 255)
                self.assertEqual(result.getpixel((0,0)), 0, "Protected source pixels stay untouched")

    def test_gallery_header_has_no_original_letter_fragments(self):
        from PIL import Image, ImageChops
        art = ROOT.parent / "design/landing/equipment"
        master = Image.open(art / "gallery-archive-master.png").convert("RGB")
        clean = Image.open(art / "gallery-archive-clean.png").convert("RGB")
        original = Image.open(art / "concepts/gallery-archive.png").convert("RGB")
        # Includes the old lower line where isolated white strokes survived.
        self.assertIsNone(ImageChops.difference(master.crop((450,75,1090,105)),clean.crop((450,75,1090,105))).getbbox())
        for box in ((310,78,436,102),(1104,78,1235,102)):
            self.assertIsNone(ImageChops.difference(master.crop(box),original.crop(box)).getbbox(), "Signal stripes must remain original")


if __name__ == "__main__":
    unittest.main()
