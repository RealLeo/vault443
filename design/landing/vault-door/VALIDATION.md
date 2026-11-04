# Exact vault-door acceptance — 2026-11-04

The two approved references are used directly as the production artwork.
The source/cleaned PNG files, deterministic text-repair rectangles, prompts and
SHA-256 manifest are in atlas/. Only recorded text surfaces were restored;
all PNG master pixels outside these rectangles are identical to the reference.

## Visual evidence

Four canonical browser captures (EN/RU × 1487×1058 desktop / 887×1774 mobile)
were compared with matching-quality WebP artwork using 50/50 overlays and
difference maps. The browser screenshot transport is JPEG, so the expected
image is encoded with identical JPEG quantization/subsampling before comparison.
Native app screenshots, translated lettering and the edited status caption
are explicitly excluded from the texture metric, not from geometry checks.
Maximum mean absolute channel error was 1.29/255, below the 2.5/255 threshold.
No texture/geometry substitutions are hidden by a full-scene comparison mask.

Both languages were checked at viewport widths 360, 390, 768, 1023, 1024, 1440
and 1920. All 14 cases have no horizontal document overflow or failed loaded
images, and Russian captions fit their intended boxes. Maximum measured slot
position/size error is 0.023 CSS px (allowed 1 CSS px). On narrow screens,
invisible hit extensions preserve at least 44 px vertical interaction areas.

Screenshots, responsive measurements, overlays, difference maps and JSON reports
are saved in test-results/website-exact-scene/ (ignored build/QA artifacts).
Authoring audit: python3 website/tools/audit_scene.py. The browser screenshot
API hides scrollbars during capture; canonical captures use the exact reference
viewport dimensions. DOM geometry is measured against actual content width.

## Functional checks

- Seven Python tests pass: release selection/fallback, native install commands,
  static EN/RU links, default open state and original/cleaned/master/WebP hashes.
- Node motion lifecycle tests and JavaScript syntax check pass. Reduced-motion
  precedence is covered by the policy tests/CSS. Actual OS emulation is not
  exposed by the browser tool and was not claimed as an OS-level browser test.
- Door replay was observed opening with visible shutters; switching motion off
  immediately hid shutters and settled open. It subsequently completed normally.
- Sound opt-in/off, screenshot zoom, Escape/focus return, feature-to-logs link,
  gallery ArrowRight, section-preserving EN/RU switching and browser Back passed.
- All three routing scenarios reached the intended active routes. Ubuntu install
  disclosure begins with checksum verification and the correct apt command.
- With scripts blocked by CSP, the door stays open, controls remain hidden and
  native download anchors/disclosures work. With GSAP intentionally unavailable,
  the door stays open and replay is disabled while content/downloads remain usable.
- Normal enhanced page has no browser console warnings/errors. Expected CSP/404
  messages belong only to deliberate fallback servers.
- Nineteen external page/download/checksum/documentation links returned HTTP 200.

## Build and publication boundaries

Online release selection confirms stable 1.3.4. Worst-case calculated first load
is approximately 1.38 MB; JavaScript is 51,120 bytes gzip. Each viewport/locale
loads its own approximately 0.65–0.68 MB atlas. Gallery screenshots remain lazy.
Python production build is still standard-library-only; Pillow is authoring/QA.
Original art remains MIT; separate font, skill and GSAP licenses are preserved.

Only landing-page implementation and design records change. Application code,
packages, public service APIs and release tag 1.3.4 are unchanged; the tag remains
64cff2b4216b4378cd5c455532667b134f4f75b9.
