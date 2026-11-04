# Vault door acceptance — 2026-11-04

The approved desktop (1487×1058) and mobile (887×1774) references are preserved
alongside the six imagegen source layers, prompts and production SHA-256 hashes.
The implementation was compared visually with both: connected chassis, broad
brass download lever, stencil serial, circular machinery/cylinder, protocol
plaques, real app window and the three feature keys. Desktop framing was tightened
after the first comparison so the status rail and feature keys fit the reference
composition. Phone protocol plaques are rearranged below the mechanism.

## Verification

- Six Python tests pass, covering release selection/fallback, installer commands,
  bilingual static links/assets, the default open door and art provenance.
- Node tests cover motion preference precedence, single session startup,
  interruption settling open, explicit replay, cross-language session reuse,
  denied storage and gallery wrapping. JavaScript syntax check passes.
- Online builder selected the real stable 1.3.4 release. Conservative initial
  resources: EN 1,079,369 bytes / RU 1,088,159 bytes; JavaScript 51,130 bytes gzip.
- Original/optimized art hashes match. Frame has a genuinely transparent center.
  Local Roboto Condensed 900 has the expected weight and Latin/Cyrillic coverage;
  pinned source, OFL license and existing third-party licenses are retained.

## In-app Chromium browser

Both EN/RU checked at 360, 390, 768, 1440 and 1920 px, plus 1023/1024 breakpoint
boundaries. No horizontal document overflow or failed loaded images. All four
installer links remain present and the hero download is in the initial viewport.
Gallery overflow discovered in the initial phone pass was corrected.

Verified actual door replay shows `opening` with visible centered shutters and
then returns to `open` with shutters hidden and replay enabled. Disabling motion
mid-sequence settles open immediately. The GSAP pixel offset is explicitly reset
so repeated shutter animations do not accumulate the initial CSS translation.
Sound opt-in/off, hero zoom, Escape/focus return, feature-to-journal navigation,
gallery End key, section-preserving language switch and the animated Docker/work
scenario were exercised. The route scenario ends with entry/work/Docker active.
No console warnings/errors on the enhanced local page.

Identical EN/RU pages served with `script-src 'none'` retain an open door, hidden
JS controls, native installation disclosures, screenshots and four downloads.
With both GSAP scripts deliberately unavailable, EN/RU remain open/static and
the enhanced gallery works. Expected script-blocking/404 messages belong to those
deliberate fallback tests. System reduced-motion precedence is covered by the
policy test and CSS/media setup; browser OS emulation was unavailable.

Local screenshots/measurements are in `test-results/website-vault-door/` (ignored
by Git), including final desktop/mobile and routing views. Review used the
[Web Interface Guidelines](https://vercel.com/design/guidelines) for keyboard,
focus, hit targets, reduced motion, readable text and progressive enhancement.

App code/packages remain unchanged. Tag 1.3.4 remains
`64cff2b4216b4378cd5c455532667b134f4f75b9`.
