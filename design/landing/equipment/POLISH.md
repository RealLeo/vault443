# Review corrections — 2026-11-04

Follow-up to the M3/G1/D2 implementation, based on the six user screenshots.

- The complete enclosure and its native content render at 75% physical scale,
  preserving source proportions and a centered maximum rendered width of 1200 px.
  Both desktop and mobile compositions use the same scale. Small interactive
  controls retain larger hit extensions. Image enlargement remains viewport sized.
- The shared metal is darker. Recessed transition strips and block/atlas vignettes
  soften the original rectangular joins and the bright lower edge of the package
  artwork. Source hardware has not been regenerated.
- Text repair masks now form a maximum-alpha union. Previously, a later feathered
  rectangle could overwrite an earlier mask with zero and restore a thin band of
  original letters. The complete routing title surface is repaired; the former
  overlap band matches the clean source exactly. A Pillow authoring regression
  test covers both artwork recipes. Protected pixels outside repairs are unchanged.
- SVG light follows measured pipe centers, with separate levels on the inlet and
  outlet of each relay. The device input follows the copper elbow. Narrow screen
  blended light replaces the broad stripe; inactive paths are transparent.
- Package captions reserve the original arrow area and fit the remaining brass
  label surface. Tests measure actual text ranges in addition to outer boxes.
- Installation commands cover the full inner CRT, including the old step outlines.
  The rounded, scrollable terminal stays inside the screen rim; long command lines
  scroll horizontally and preserve their exact copyable contents.
- Both language selectors use native grid captions inside measured plate interiors.
  The English atlas's painted selector text is cleared as well. The English and
  Russian selectors use identical geometry and include keyboard focus.
- Sound is now enabled by default, as explicitly requested in this review. Web
  Audio unlocks on the first trusted click/key gesture under browser autoplay
  policy. Immediate mute remains available; reload/language/BFCache restore the
  default enabled state. This supersedes the earlier default-off acceptance.
- Styles, script and revised atlases have content-hash query versions, preventing
  stale cached assets from being combined with new HTML. Native section jumps are
  immediate. ScrollTrigger refresh is called only when an actual trigger exists,
  avoiding unnecessary interference with native anchor scrolling.

## Validation

EN/RU × 360, 390, 768, 1023, 1024, 1440 and 1920 px: all 14 cases pass. Rendered
width is exactly 0.75 × min(viewport width, 1600 px). No document overflow,
overflowing captions, failed loaded images or Download/language text collisions.
Screenshots and measurements: `test-results/website-polish/` (ignored QA output).

Three route sequences, four command disclosures, gallery arrows/zoom/Escape/focus,
default sound/mute, language preservation, reload/Back and no-JS/no-GSAP fallback
passed browser checks. The ordinary page emits no console warnings/errors.
Eleven Python tests pass locally, including the optional Pillow regression;
environments without Pillow skip only that authoring test. Node motion lifecycle,
JavaScript syntax, static links and asset hashes also pass.

The source app, release packages and tag 1.3.4 are unchanged.
