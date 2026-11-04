# Caption, indicator and copy review — 2026-11-04

Desktop keeps the approved 75% scale and 1200 px rendered maximum. Below 1024 px,
the existing mobile composition now fills the available content width at zoom 1.
Native/mobile controls and hit extensions provide at least 44×44 CSS px targets.

## Measured surfaces

`website/data/equipment-layout.json` now distinguishes hardware hit rectangles,
inner caption rectangles, icon obstacles and individual lens centers/radii. The
CSS authoring recipe converts these source coordinates into local percentages.
Previous/next/enlarge hit boxes cover the actual source frames. Their captions,
the demo states, getting-started plate, scenario keys, package controls and node
labels use the clear surface between icons, glass and bolts. Recorded icon gaps
are at least 12 source pixels. Gallery and scenario key groups use common sizes;
demo start/running/replay retain the same font size.

The browser refines native span alignment using local-font Canvas text metrics,
including actual glyph bearings, ascent/descent and wrapped lines. ResizeObserver,
font-load and text-change callbacks queue one batched read/write pass. This adds
no animation or dependency. HTML/CSS still supplies readable, centered labels
without scripts. No generated UI lettering or substitute hardware was introduced.

The gallery title/subtitle repair is one continuous surface, bounded before the
signal stripes. Its lower line no longer restores isolated strokes from old text.
The existing cleaned PNG is reused; the original frame, bolts and both signal
stripes remain unchanged. Updated PNG/WebP hashes are in the artwork manifest.

## Copy and content

EN/RU use the approved benefit-focused copy with light console vocabulary for
profiles, work networks, diagnostics, routing, gallery and downloads. The gallery
has a short separate demo-profile note. The Ubuntu/Debian package distinction,
checksum steps, system requirements, Fedora/Arch status, full-tunnel work-VPN
restriction and Docker route behavior remain visible. App APIs, packages, tag
1.3.4 and the existing door/audio policies are unchanged.

## Acceptance

- EN/RU at 360, 390, 768, 1023, 1024, 1440 and 1920 px: all 14 cases pass,
  with no horizontal overflow, clipped caption text or failed loaded images.
- Visible glyph bounds are checked against the actual caption area using font
  bearings and line metrics. Maximum measured center error: 0.019 CSS px.
  Maximum lens-center error: 0.016 CSS px (allowed 1 px).
- All measured mobile interaction targets are at least 44×44 CSS px. Full-width
  mobile and 75% desktop dimensions match the requested breakpoints exactly.
- Demo start/running/replay use the same measured 40.32 px font at a 1440 px
  viewport. Six gallery choices each produce one active indicator and the correct
  localized screenshot. Arrow/End, zoom, Escape/focus return, four install command
  disclosures, immediate mute and no-JS/no-GSAP fallback pass browser checks.
- Thirteen Python tests, Node motion lifecycle and JS syntax pass locally.
  Optional Pillow tests cover overlapping masks, the cleaned subtitle band and
  original signal stripes. Geometry checks protect caption clearances and lenses.
- Existing build budgets pass: core initial assets stay below 1.5 MB; JavaScript
  stays below 100 KB gzip. Lower artwork remains deferred near the viewport.

Control screenshots and measurements are retained in
`test-results/website-alignment/` as ignored QA artifacts. The production builder
continues to use only the Python standard library.
