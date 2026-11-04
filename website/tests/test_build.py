import copy
from html.parser import HTMLParser
import importlib.util
import json
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("site_builder", ROOT / "build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class WebsiteTests(unittest.TestCase):
    def setUp(self):
        self.release = json.loads((ROOT / "data/release.json").read_text())

    def test_complete_snapshot_and_distribution_commands(self):
        selected = builder.select_release(self.release)
        self.assertEqual(selected["version"], "1.3.4")
        self.assertEqual(len(selected["packages"]), 4)
        for package, manager in zip(selected["packages"], ("apt", "apt", "dnf", "pacman")):
            command = builder.install_commands(package)
            self.assertTrue(command.startswith("sha256sum -c "))
            self.assertIn("sudo " + manager, command)
            self.assertIn(package["filename"], command)
            self.assertTrue(command.endswith('sudo vault443-access "$USER"'))

    def test_incomplete_release_rejected(self):
        for asset in self.release["assets"]:
            if asset["name"].endswith(".sha256") or asset["name"] == "SHA256SUMS":
                incomplete = copy.deepcopy(self.release)
                incomplete["assets"] = [item for item in incomplete["assets"] if item["name"] != asset["name"]]
                with self.subTest(asset=asset["name"]), self.assertRaises((ValueError, KeyError)):
                    builder.select_release(incomplete)

    def test_prerelease_and_untrusted_url_rejected(self):
        bad = copy.deepcopy(self.release)
        bad["prerelease"] = True
        with self.assertRaises(ValueError):
            builder.select_release(bad)
        bad = copy.deepcopy(self.release)
        for asset in bad["assets"]:
            asset["browser_download_url"] = "https://example.org/installer"
        with self.assertRaises(ValueError):
            builder.select_release(bad)

    def test_network_failure_and_incomplete_latest_fall_back(self):
        with patch.object(builder.urllib.request, "urlopen", side_effect=OSError("offline")):
            self.assertEqual(builder.load_release()["version"], "1.3.4")
        with patch.object(builder, "select_release", side_effect=[ValueError("missing asset"), {"version": "1.3.4"}]):
            with patch.object(builder.urllib.request, "urlopen") as response:
                response.return_value.__enter__.return_value.read.return_value = b'{}'
                self.assertEqual(builder.load_release()["version"], "1.3.4")

    def test_static_links_localization_and_assets(self):
        selected = builder.select_release(self.release)
        en = json.loads((ROOT / "data/en.json").read_text())
        ru = json.loads((ROOT / "data/ru.json").read_text())
        self.assertEqual(builder.translation_keys(en), builder.translation_keys(ru))
        for locale in (en, ru):
            page = builder.render_page(locale, selected, "/vault443/")
            parser = Links()
            parser.feed(page)
            self.assertNotIn("{{", page)
            ids = {attrs["id"] for tag, attrs in parser.elements if "id" in attrs}
            for tag, attrs in parser.elements:
                for key in ("href", "src"):
                    url = attrs.get(key, "")
                    if url.startswith("#"):
                        self.assertIn(url[1:], ids)
                    if url.startswith("/vault443/assets/") and not url.endswith("social.png"):
                        self.assertTrue((ROOT / "assets" / url.removeprefix("/vault443/assets/").split("?",1)[0]).is_file(), url)
            downloads = [attrs for tag, attrs in parser.elements if tag == "a" and "package-download" in attrs.get("class", "")]
            self.assertEqual(len(downloads), 4, "Static HTML must contain the real download links")
            self.assertIn('lang="' + locale["lang"] + '"', page)
            self.assertIn('hreflang="x-default"', page)
            self.assertTrue(all(attrs.get("alt") is not None for tag, attrs in parser.elements if tag == "img"))

    def test_door_static_state_and_art_provenance(self):
        selected = builder.select_release(self.release)
        data = json.loads((ROOT / "data/en.json").read_text())
        page = builder.render_page(data, selected, "/vault443/")
        parser = Links()
        parser.feed(page)
        assemblies = [attrs for tag, attrs in parser.elements if "vault-assembly" in attrs.get("class", "").split()]
        self.assertEqual(assemblies[0]["data-door-state"], "open")
        self.assertIn('class="scene-protocols visually-hidden"', page)
        for protocol in ("VLESS", "Trojan", "OpenVPN", "Shadowsocks / Outline", "WireGuard", "AmneziaWG"):
            self.assertIn('<li>' + protocol + '</li>', page)
        self.assertIn('href="/vault443/assets/screens/en/main.webp" data-hero-preview', page)
        self.assertIn('class="system-controls" data-js-only hidden', page)
        artwork = json.loads((ROOT.parent / "design/landing/vault-door/manifest.json").read_text())
        for item in artwork["assets"]:
            with self.subTest(asset=item["name"]):
                self.assertEqual(hashlib.sha256((ROOT.parent / item["original"]).read_bytes()).hexdigest(), item["sha256"])
                self.assertEqual(hashlib.sha256((ROOT.parent / item["production"]).read_bytes()).hexdigest(), item["productionSha256"])
        frame = next(item for item in artwork["assets"] if item["name"] == "vault-frame")
        self.assertTrue(frame["alpha"])
        self.assertEqual(frame["centerAlpha"], 0)

    def test_exact_scene_geometry_and_provenance(self):
        layout = json.loads((ROOT / "data/scene-layout.json").read_text())
        self.assertEqual(layout["desktop"]["size"], [1487, 1058])
        self.assertEqual(layout["mobile"]["size"], [887, 1774])
        for mode, scene in layout.items():
            width, height = scene["size"]
            for name, (x, y, w, h) in scene["slots"].items():
                self.assertGreaterEqual(x, 0)
                self.assertGreaterEqual(y, 0)
                self.assertLessEqual(x+w, width, name)
                self.assertLessEqual(y+h, height, name)
            self.assertEqual(len(scene["cams"]), 6)
        artwork = json.loads((ROOT.parent / "design/landing/vault-door/atlas/manifest.json").read_text())
        self.assertEqual(len(artwork["assets"]), 4)
        for item in artwork["assets"]:
            for path, digest in (("reference", "referenceSha256"), ("cleaned", "cleanedSha256"), ("master", "masterSha256"), ("production", "productionSha256")):
                self.assertEqual(hashlib.sha256((ROOT.parent / item[path]).read_bytes()).hexdigest(), item[digest])
            self.assertEqual(item["size"], layout[item["mode"]]["size"])
            self.assertIn("brand", item["repairs"])
        for lang in ("en", "ru"):
            data = json.loads((ROOT / "data" / (lang + ".json")).read_text())
            page = builder.render_page(data, builder.select_release(self.release), "/vault443/")
            self.assertIn('scene/mobile-' + lang + '.webp', page)
            self.assertNotIn('stencil-443.svg', page)
            self.assertNotIn('<strong>Vault 443</strong>', page)

    def test_equipment_controls_and_deferred_decoration(self):
        selected = builder.select_release(self.release)
        for lang in ("en", "ru"):
            data = json.loads((ROOT / "data" / (lang + ".json")).read_text())
            page = builder.render_page(data, selected, "/vault443/")
            parser = Links(); parser.feed(page)
            for removed in ("motion-button", "door-replay", "gallery-shutter"):
                self.assertNotIn(removed, page)
            atlases = [attrs for tag, attrs in parser.elements if "data-art-src" in attrs]
            self.assertEqual(len(atlases), 3)
            self.assertTrue(all("src" not in attrs for attrs in atlases))
            for tag, attrs in parser.elements:
                for key in ("data-art-src", "data-part-src", "data-mobile-src"):
                    if key in attrs:
                        self.assertTrue((ROOT / "assets" / attrs[key].split("/assets/")[1].split("?",1)[0]).is_file())
            summaries = [attrs for tag, attrs in parser.elements if tag == "summary" and "ed-install-" in attrs.get("class", "")]
            self.assertEqual(len(summaries), 4)
            choices = [attrs for tag, attrs in parser.elements if tag == "a" and "gallery-choice" in attrs.get("class", "").split()]
            self.assertEqual(len(choices), 6)
            self.assertTrue(all(attrs["href"].endswith(".webp") for attrs in choices))

    def test_sound_default_and_cache_safe_references(self):
        data = json.loads((ROOT / "data/en.json").read_text())
        page = builder.render_page(data, builder.select_release(self.release), "/vault443/")
        parser = Links(); parser.feed(page)
        button = next(attrs for tag,attrs in parser.elements if "sound-button" in attrs.get("class", ""))
        self.assertEqual(button["aria-pressed"], "true")
        for name in ("main.js", "polish.css", "equipment/routing-relays.webp"):
            digest = hashlib.sha256((ROOT / "assets" / name).read_bytes()).hexdigest()[:12]
            self.assertIn("/vault443/assets/" + name + "?v=" + digest, page)

    def test_equipment_artwork_and_coordinate_integrity(self):
        art = ROOT.parent / "design/landing/equipment"
        concepts = json.loads((art / "concepts.json").read_text())["concepts"]
        self.assertEqual(len(concepts), 9)
        self.assertEqual(sum(item["selected"] for item in concepts), 3)
        for item in concepts:
            self.assertTrue(item["prompt"])
            self.assertEqual(hashlib.sha256((ROOT.parent / item["original"]).read_bytes()).hexdigest(), item["sha256"])
        manifest = json.loads((art / "manifest.json").read_text())
        for asset in manifest["assets"]:
            for key, digest in (("reference", "referenceSha256"), ("clean", "cleanSha256"), ("master", "masterSha256"), ("production", "productionSha256")):
                self.assertEqual(hashlib.sha256((ROOT.parent / asset[key]).read_bytes()).hexdigest(), asset[digest])
        for part in manifest["parts"] + [manifest["texture"]]:
            self.assertEqual(hashlib.sha256((ROOT.parent / part["production"]).read_bytes()).hexdigest(), part["sha256"])
        layout = json.loads((ROOT / "data/equipment-layout.json").read_text())
        for scene in layout.values():
            self.assertEqual(scene["size"], [1536, 1024])
            for name, (x, y, w, h) in scene["slots"].items():
                self.assertTrue(0 <= x < x+w <= 1536, name)
                self.assertTrue(0 <= y < y+h <= 1024, name)

    def test_caption_clearances_and_individual_lenses(self):
        layout = json.loads((ROOT / "data/equipment-layout.json").read_text())
        self.assertEqual(len(layout["gallery"]["lamps"]), 6)
        for scene in layout.values():
            for name, (x,y,w,h) in scene.get("captions", {}).items():
                px,py,pw,ph = scene["slots"][name]
                self.assertTrue(px <= x < x+w <= px+pw, name)
                self.assertTrue(py <= y < y+h <= py+ph, name)
                for obstacle in scene.get("captionObstacles", {}).get(name, []):
                    ox,oy,ow,oh = obstacle["rect"]
                    gap = x-(ox+ow) if obstacle["side"] == "left" else ox-(x+w)
                    self.assertGreaterEqual(gap, 12, name)
            for name, lamp in scene.get("lamps", {}).items():
                x,y,w,h = scene["slots"][name];cx,cy=lamp["center"];r=lamp["radius"]
                self.assertTrue(x < cx-r < cx+r < x+w)
                self.assertTrue(y < cy-r < cy+r < y+h)
        data = json.loads((ROOT / "data/ru.json").read_text())
        page = builder.render_page(data,builder.select_release(self.release),"/vault443/")
        self.assertIn(data["equipment"]["galleryNote"],page)
        self.assertIn(data["equipment"]["packageNote"],page)
        self.assertNotIn("Настоящие элементы управления",page)


if __name__ == "__main__":
    unittest.main()
