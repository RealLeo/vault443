#!/usr/bin/env python3
"""Build the bilingual GitHub Pages site using only the Python standard library."""
import argparse
import fnmatch
import gzip
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
REPOSITORY = "https://github.com/RealLeo/vault443"
SITE = "https://realleo.github.io"
TARGETS = {
    "ubuntu": {"name": "Ubuntu 24.04 / 26.04", "pattern": "vault443_{version}-*ubuntu24.04_amd64.deb", "format": ".deb"},
    "debian": {"name": "Debian 13", "pattern": "vault443_{version}-*debian13_amd64.deb", "format": ".deb"},
    "fedora": {"name": "Fedora 44", "pattern": "vault443-{version}-*.fc44.x86_64.rpm", "format": ".rpm"},
    "arch": {"name": "Arch Linux", "pattern": "vault443-{version}-*-x86_64.pkg.tar.zst", "format": ".pkg.tar.zst"},
}


class Markup(str):
    """HTML produced by this renderer, never supplied by a translation or API."""


def escape(value):
    return html.escape(str(value), quote=True)


def select_release(release):
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("Only public stable releases may supply downloads")
    tag = release["tag_name"]
    version = tag.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Unsupported release version")
    prefix = REPOSITORY + "/releases/download/" + urllib.parse.quote(tag, safe="") + "/"
    assets = {item["name"]: item for item in release["assets"] if item.get("state", "uploaded") == "uploaded" and item.get("size", 0) > 0}

    def url(name):
        value = assets[name]["browser_download_url"]
        if value != prefix + urllib.parse.quote(name, safe="._-"):
            raise ValueError("Unexpected release asset URL")
        return value

    packages = []
    for target, info in TARGETS.items():
        matches = [name for name in assets if fnmatch.fnmatchcase(name, info["pattern"].format(version=version))]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one {target} installer")
        name = matches[0]
        if not re.fullmatch(r"[A-Za-z0-9._+-]+", name):
            raise ValueError("Unsafe installer filename")
        packages.append(dict(target=target, name=info["name"], filename=name,
                             format=info["format"], url=url(name), checksum=url(name + ".sha256"),
                             size=assets[name]["size"]))
    return dict(version=version, tag=tag, url=REPOSITORY + "/releases/tag/" + urllib.parse.quote(tag, safe=""),
                sums=url("SHA256SUMS"), packages=packages)


def load_release(offline=False):
    if not offline:
        try:
            request = urllib.request.Request("https://api.github.com/repos/RealLeo/vault443/releases/latest",
                                             headers={"User-Agent": "Vault443-Pages-builder", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(request, timeout=15) as response:
                selected = select_release(json.load(response))
            print("Release API:", selected["version"])
            return selected
        except (OSError, ValueError, KeyError, TypeError) as error:
            print("Release API unavailable or incomplete; using verified snapshot:", type(error).__name__)
    selected = select_release(json.loads((ROOT / "data/release.json").read_text()))
    print("Verified snapshot:", selected["version"])
    return selected


def lookup(data, key):
    value = data
    for part in key.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def translation_keys(value, prefix=""):
    if isinstance(value, dict):
        return {key for name, child in value.items() for key in translation_keys(child, prefix + "." + name)}
    if isinstance(value, list):
        return {key for index, child in enumerate(value) for key in translation_keys(child, prefix + "." + str(index))}
    return {prefix}


def install_commands(package):
    name = package["filename"]
    lines = ["sha256sum -c " + name + ".sha256"]
    target = package["target"]
    if target in ("ubuntu", "debian"):
        lines.append("sudo apt install ./" + name)
    elif target == "fedora":
        lines.append("sudo dnf install ./" + name)
    else:
        lines.extend(["sudo pacman -Syu", "sudo pacman -U ./" + name])
    if target in ("fedora", "arch"):
        lines.append("sudo systemctl enable --now vault443-guard.service vault443.service")
    lines.append('sudo vault443-access "$USER"')
    return "\n".join(lines)



def equipment_values(data, release, assets, gallery):
    t = lambda key: escape(lookup(data, key))
    image = lambda name: '<img class="mobile-part" data-mobile-src="' + assets + 'equipment/' + name + '.webp" alt="">'
    values = {}
    values["scenario_choices"] = Markup("".join(
        '<label class="e-slot scenario-choice er-scenario-' + str(i) + '"><input type="radio" name="scenario" value="' + str(i) + '"' + (' checked' if i == 0 else '') + '><span class="e-label">' + escape(item["short"]) + '</span></label>'
        for i, item in enumerate(data["demo"]["scenarios"])))
    channels = []
    for i, route in enumerate(("internet", "work", "docker")):
        label = data["demo"]["nodes"][route]
        channels.append('<div class="relay-channel" data-channel="' + route + '" data-active="' + ('true' if i == 0 else 'false') + '"><div class="e-slot relay-body er-relay-' + str(i) + '">' + image("relay-body") + '<img class="relay-arm" data-part-src="' + assets + 'equipment/relay-arm-' + str(i) + '.webp" width="255" height="136" alt=""><span class="channel-lamp" aria-hidden="true"></span></div><svg class="mobile-wire" viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true"><path class="route-wire" data-route="' + route + '" pathLength="100" d="M0 8H100"/></svg><div class="e-slot destination-node er-destination-' + str(i) + '">' + image("destination-" + str(i)) + '<span>' + escape(label) + '</span></div></div>')
    values["relay_channels"] = Markup("".join(channels))
    values["gallery_links"] = Markup("".join(
        '<a class="e-slot gallery-choice eg-choice-' + str(i) + (' is-active' if i == 0 else '') + '" href="' + item["src"] + '" data-gallery-index="' + str(i) + '"' + (' aria-current="true"' if i == 0 else '') + '>' + image("gallery-key-" + str(i)) + '<span class="e-label">' + escape(item["short"]) + '</span><i class="choice-lamp" aria-hidden="true"></i></a>'
        for i, item in enumerate(gallery)))
    rows, support = [], []
    for i, package in enumerate(release["packages"]):
        target = package["target"]
        status = data["downloads"]["established" if target == "ubuntu" else "port" if target in ("fedora", "arch") else "native"]
        support.append(package["name"] + " — " + status)
        number = f'{package["size"] / 1048576:.1f}'
        if data["lang"] == "ru": number = number.replace(".", ",")
        activation = '<p class="activation-note">' + t("downloads.activation") + '</p>' if target in ("fedora", "arch") else ''
        rows.append('<article class="e-package"><div class="distro-emblem">' + image("distro-" + str(i)) + '</div><h3 class="e-slot ed-name-' + str(i) + '">' + escape(package["name"]) + '</h3><span class="e-slot package-format ed-format-' + str(i) + '">' + escape(package["format"]) + '</span><span class="e-slot package-size ed-size-' + str(i) + '"><span>' + number + '</span><small>' + ('МБ' if data["lang"] == "ru" else 'MB') + '</small></span><p class="e-slot e-package-status ed-status-' + str(i) + (' established-status' if i < 2 else '') + '">' + escape(status) + '</p><a class="e-slot equipment-key package-download ed-download-' + str(i) + '" href="' + escape(package["url"]) + '"><span>' + t("downloads.download") + '</span></a><a class="e-slot equipment-key checksum-link ed-sum-' + str(i) + '" href="' + escape(package["checksum"]) + '">' + t("downloads.checksum") + '<span class="e-key-hit" aria-hidden="true"></span></a><details class="install-details e-install"><summary class="e-slot equipment-key ed-install-' + str(i) + '">' + t("downloads.install") + '<span class="e-key-hit" aria-hidden="true"></span></summary><div class="install-content"><p class="installation-title">' + escape(package["name"]) + '</p>' + activation + '<div class="command-box"><pre tabindex="0"><code id="commands-' + target + '">' + escape(install_commands(package)) + '</code></pre><button class="copy-button" type="button" data-copy="commands-' + target + '" data-js-only hidden>' + t("downloads.copy") + '</button></div></div></details></article>')
    values["download_rows"] = Markup("".join(rows))
    values["support_summary"] = "; ".join(support) + "."
    values["equipment_steps"] = Markup("".join('<li class="e-slot ed-step-' + str(i) + '"><span class="step-number" aria-hidden="true">' + str(i+1) + '</span><div><strong>' + escape(item["title"]) + '</strong><p>' + escape(item["body"]) + '</p></div></li>' for i, item in enumerate(data["equipment"]["steps"])))
    return values


def render_page(translations, release, base):
    data = translations
    lang = data["lang"]
    assets = base + "assets/"
    t = lambda key: escape(lookup(data, key))
    screen_url = lambda name: assets + "screens/" + lang + "/" + name + ".webp"
    other = base + "ru/" if lang == "en" else base
    values = dict(data)
    values.update(assets=assets, canonical=SITE + (base if lang == "en" else base + "ru/"),
                  english_url=SITE + base, russian_url=SITE + base + "ru/", og_locale="en_US" if lang == "en" else "ru_RU",
                  social_image=SITE + assets + "social.png", hero_image=screen_url("main"),
                  release_version=release["version"], release_url=release["url"], sums_url=release["sums"],
                  readme_url=REPOSITORY + "/blob/main/" + ("README.md" if lang == "en" else "README.ru.md"),
                  start_anchor="first-connection", recovery_url=REPOSITORY + "/blob/main/" + ("README.md#troubleshooting-and-recovery" if lang == "en" else "README.ru.md#" + urllib.parse.quote("диагностика-и-восстановление-сети")))
    language_parts = []
    for code in ("en", "ru"):
        if code == lang:
            language_parts.append('<span lang="' + code + '" aria-current="page">' + code.upper() + '</span>')
        else:
            language_parts.append('<a class="language-link" href="' + other + '" lang="' + code + '" hreflang="' + code + '">' + code.upper() + '</a>')
    values["scene_language_links"] = Markup(language_parts[0] + '<span aria-hidden="true">/</span>' + language_parts[1])
    destinations = ["#screenshots", "#routes", "#screenshots"]
    values["scene_feature_links"] = Markup("".join('<a class="scene-slot scene-feature-' + str(index + 1) + ' scene-key" href="' + destinations[index] + '"' + (' data-feature-screen="logs"' if index == 2 else '') + '><span class="scene-caption">' + escape(item["title"]) + '</span></a>' for index, item in enumerate(data["features"])))
    values["feature_rows"] = Markup("".join('<article><h2>' + escape(item["title"]) + '</h2><p>' + escape(item["body"]) + '</p></article>' for item in data["features"]))
    values["scene_cams"] = Markup("".join('<span class="scene-slot vault-cam cam-' + str(index) + '"><span class="cam-sprite"></span></span>' for index in range(1, 7)))
    values["scene_lamps"] = Markup("".join('<span class="scene-slot lamp-shade lamp-' + str(index) + '" aria-hidden="true"></span>' for index in range(1, 10)))
    values["static_scenarios"] = Markup("".join('<details><summary>' + escape(item["name"]) + '</summary><p>' + escape(item["description"]) + '</p></details>' for item in data["demo"]["scenarios"]))
    gallery = [dict(item, src=screen_url(item["file"])) for item in data["gallery"]["screens"]]
    values["gallery_first_image"] = gallery[0]["src"]
    values.update(equipment_values(data, release, assets, gallery))
    values["setup_steps"] = Markup("".join('<li><h3>' + escape(item["title"]) + '</h3><p>' + escape(item["body"]) + '</p></li>' for item in data["setup"]["steps"]))
    values["faq_items"] = Markup("".join('<details><summary>' + escape(item["question"]) + '</summary><p>' + escape(item["answer"]) + '</p></details>' for item in data["faq"]["items"]))
    values["page_data"] = Markup(json.dumps(dict(controls=data["controls"], demo=data["demo"], gallery=gallery,
                                                 hero=dict(src=screen_url("main"), alt=data["hero"]["alt"], caption=data["hero"]["caption"]),
                                                 downloads={key: data["downloads"][key] for key in ("copy", "copied", "copyFailed")}), ensure_ascii=False).replace("<", "\\u003c"))

    def substitute(match):
        key = match.group(1)
        value = values[key] if key in values else lookup(data, key)
        return value if isinstance(value, Markup) else escape(value)
    template = (ROOT / "templates/index.html").read_text().replace("{{hero_panel}}", (ROOT / "templates/hero.html").read_text()).replace("{{equipment_panels}}", (ROOT / "templates/equipment.html").read_text())
    page = re.sub(r"\{\{\s*([\w.]+)\s*\}\}", substitute, template)
    # Cache-safe replacements for CSS/JS and revised measured atlases.
    versioned = ["style.css", "vault.css", "scene.css", "scene-layout.css", "equipment.css", "equipment-layout.css", "polish.css", "main.js"]
    versioned += [f"scene/{mode}-{code}.webp" for mode in ("desktop", "mobile") for code in ("en", "ru")]
    versioned += [f"equipment/{name}.webp" for name in ("routing-relays", "gallery-archive", "downloads-counter")]
    for name in versioned:
        digest = hashlib.sha256((ROOT / "assets" / name).read_bytes()).hexdigest()[:12]
        page = page.replace(assets + name, assets + name + "?v=" + digest)
    return page


def build(base="/vault443/", offline=False):
    if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*", base):
        raise ValueError("Base must be a slash-delimited path")
    locales = {lang: json.loads((ROOT / "data" / (lang + ".json")).read_text()) for lang in ("en", "ru")}
    if translation_keys(locales["en"]) != translation_keys(locales["ru"]):
        raise ValueError("English and Russian translation structures differ")
    release = load_release(offline)
    with tempfile.TemporaryDirectory(prefix="vault443-site-") as folder:
        stage = Path(folder)
        shutil.copytree(ROOT / "assets", stage / "assets")
        shutil.copy2(ROOT.parent / "docs/images/readme/main.png", stage / "assets/social.png")
        for lang, content in locales.items():
            destination = stage if lang == "en" else stage / "ru"
            destination.mkdir(exist_ok=True)
            (destination / "index.html").write_text(render_page(content, release, base))
        (stage / ".nojekyll").write_text("")
        (stage / "release.json").write_text(json.dumps(release, ensure_ascii=False, indent=2) + "\n")
        (stage / "sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + SITE + base + '</loc></url><url><loc>' + SITE + base + 'ru/</loc></url></urlset>\n')
        (stage / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: " + SITE + base + "sitemap.xml\n")
        (stage / "404.html").write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Page not found — Vault 443</title><link rel="stylesheet" href="' + base + 'assets/style.css"><main class="container section"><h1>Page not found / Страница не найдена</h1><p><a class="metal-button" href="' + base + '">English</a> <a class="metal-button" href="' + base + 'ru/">Русский</a></p></main></html>')
        for page in (stage / "index.html", stage / "ru/index.html"):
            if "{{" in page.read_text():
                raise ValueError("Unresolved template variable")
        output = ROOT / "dist"
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(stage, output)
    # Count hero layers, HTML, scripts, styles, fonts and the shared material.
    # Lower equipment atlases/parts and gallery screens load only near the viewport.
    initial = ["style.css", "vault.css", "scene.css", "scene-layout.css", "equipment.css", "equipment-layout.css", "polish.css", "main.js", "vendor/gsap.min.js", "vendor/ScrollTrigger.min.js", "fonts/vault-terminal.woff2", "fonts/vault-condensed.woff2", "fonts/vault-display.woff2", "emblem.webp", "vault/hatch-shutters.webp", "equipment/steel-seamless.webp"]
    shared = sum((ROOT / "assets" / name).stat().st_size for name in initial)
    totals = {lang: {mode: shared + (ROOT / "assets/scene" / f"{mode}-{lang}.webp").stat().st_size + (ROOT / "assets/screens" / lang / "main.webp").stat().st_size + (output / ("index.html" if lang == "en" else "ru/index.html")).stat().st_size for mode in ("desktop", "mobile")} for lang in locales}
    total = max(value for modes in totals.values() for value in modes.values())
    js_gzip = sum(len(gzip.compress((ROOT / "assets" / name).read_bytes(), mtime=0)) for name in ["main.js", "vendor/gsap.min.js", "vendor/ScrollTrigger.min.js"])
    if total > 1_500_000 or js_gzip > 100_000:
        raise ValueError(f"Initial load budget exceeded: {total} bytes, JS gzip {js_gzip}")
    (output / "budgets.json").write_text(json.dumps(dict(initial_bytes={lang: max(modes.values()) for lang, modes in totals.items()}, initial_bytes_by_viewport=totals, javascript_gzip_bytes=js_gzip), indent=2) + "\n")
    print(f"Built EN/RU for {base}; initial assets {totals}; JavaScript gzip {js_gzip:,} bytes")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Use the checked-in verified release snapshot")
    parser.add_argument("--base", default="/vault443/")
    args = parser.parse_args()
    build(args.base, args.offline)
