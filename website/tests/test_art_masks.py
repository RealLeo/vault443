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


if __name__ == "__main__":
    unittest.main()
