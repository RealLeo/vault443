# Equipment bays: M3 + G1 + D2

The approved first-screen scene is retained. Three selected 1536×1024 concepts
continue the same enclosure: M3 (relay cabinet), G1 (archive terminal), and D2
(package counter). All nine concepts are in `concepts/`; `concepts.json` records
their original paths, full generation prompts, selections and SHA-256 hashes.

## Artwork and native UI

The production atlases use the original concept PNGs directly. Built-in imagegen
repaired only text surfaces and stateful equipment surfaces, using each selected
concept as its reference. The complete repair prompts and output hashes are in
`repairs.json`. `website/tools/prepare_equipment.py` composites those repairs into
recorded, feathered rectangles; it never replaces the whole reference image.
Every original pixel outside those rectangles is preserved in the PNG masters.
`manifest.json` records all original, repaired, master and WebP hashes.

The authoring script also extracts actual relay arms, mobile equipment parts and
nine-slice key rims. No substitute equipment is drawn. On desktop, the atlas is
proportionally scaled inside a 1536:1024 bay; live HTML occupies source coordinates
in `website/data/equipment-layout.json`. Text, version, package sizes, downloads,
checksums, commands and indicators are native HTML/SVG. App previews are genuine,
unmodified EN/RU demo screenshots with `object-fit: contain`.

Below 1024 px the same parts form a readable stacked composition: scenario keys
above the routing equipment, six gallery keys in two columns above a fixed screen,
and four installer rows followed by instructions. Buttons use the extracted rims.
No section duplicates the hero's circular vault door.

The new evenly lit metal material is mirrored into an exactly periodic 256×256
lossless WebP tile. Opposite decoded edge rows/columns are identical. A separate
CSS gradient supplies the lighting, so expansion of the FAQ introduces no baked
lighting seam. The material and all generated website artwork remain under the
project MIT license; no Fallout game assets are distributed.

## Motion and fallbacks

The existing 900 ms hero timeline runs on each new document and on persisted
`pageshow` restoration. There is no storage flag, motion toggle or door replay
button. Reduced motion, missing GSAP and missing JavaScript leave the door open.
Gallery transitions change only screenshot opacity. Route demos move the actual
contact arm sprites and light selected routes in sequence, retaining the final
state. Demo replay remains available.

Sound starts disabled on every document and BFCache restoration; an explicit
button opts in. Disabling it silences current oscillators immediately. There are
no perpetual background animations or client-side GitHub API requests.

Lower atlases and device parts have deferred source attributes. IntersectionObserver
loads the relevant desktop/mobile art near the viewport. Core text, image links,
all four downloads, checksum links and native command disclosures remain usable
without scripts. Desktop command disclosures use the right CRT; mobile commands
expand within their corresponding package row.

## Reproduction

Production build (Python standard library only):

```sh
python3 website/build.py --offline
python3 -m unittest discover -s website/tests -v
node website/tests/motion.cjs
```

Artwork authoring and visual audit additionally use Pillow:

```sh
python3 website/tools/prepare_equipment.py
python3 website/tools/audit_equipment.py
```

For canonical captures, `website/tools/serve.py --section routes` (or
`screenshots` / `download`) hides other sections without changing the real section
DOM or JavaScript. Capture the exact 1536×1024 viewport. `--no-js` and `--no-gsap`
provide explicit fallback previews. QA artifacts are ignored under
`test-results/website-equipment/`.
