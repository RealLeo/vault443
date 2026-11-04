# Vault door reference implementation

The approved reference-desktop.png (1487×1058) and reference-mobile.png
(887×1774) are the source artwork, not a style approximation. The hero extends
from the masthead through the three feature plates. It uses one responsive
atlas with measured HTML links and a real, proportional EN/RU app screenshot.
The entire composition scales uniformly, switches at 1024 px, and caps at 1600 px.

Painted 443, emblem, hydraulics, door rim, locking blocks, protocol plates,
lamps, fasteners and all framing retain the original source pixels. Do not
regenerate these elements or substitute CSS approximations. The sole decorative
Vault 443 title is in the masthead; the real app title stays in its screenshot.

Built-in imagegen repaired the materials beneath removed/replaced lettering.
Its full outputs are immutable in atlas/text-clean-*.png. prepare_scene.py limits
repairs to the recorded rectangles, mechanically composites them over the original,
and encodes quality95 WebP. Pixels outside these rectangles are unchanged in the
PNG masters. Sources, prompts, masks and SHA-256 provenance are in atlas/.

English plate lettering is retained directly in the source artwork for exact
fidelity; real HTML supplies semantic text and interaction. Russian captions
use local Roboto Condensed on the repaired surfaces. Forced-colors/print expose
the native HTML labels. Protocol names remain identical in both locales.

Coordinates are recorded in website/data/scene-layout.json. Authoring-only
prepare_scene.py also writes scene-layout.css; the production Python build needs
only the standard library. Picture media selection and CSS variables load only
the matching locale/viewport atlas. Do not preload both variants.

Only the real app preview differs inside the measured window; object-fit:contain
preserves its native proportions. Original atlas locking nuts are clipped as CSS
sprites during the 900 ms startup, then hidden to reveal the exact source art.
Lamp darkening masks disappear and screen glow returns to zero at completion.
Two existing shutters cover only the app aperture while opening. No infinite motion.

The session-wide startup, reduced-motion policy, interruption, replay, opt-in
sound and static/no-GSAP fallbacks are retained. Motion/sound/replay and feature
explanations sit below the exact composition. Supporting sections and downloads
retain their existing content, anchors and release snapshot.
