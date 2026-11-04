# Landing acceptance — 2026-11-04

Site implementation: `1bd89f415c01f69effb7c667e8d96da91924fb42`.
Deployment: [successful official Pages workflow](https://github.com/RealLeo/vault443/actions/runs/41821460357).
Public URLs: [English](https://realleo.github.io/vault443/),
[Russian](https://realleo.github.io/vault443/ru/).

## Automated checks

- Five Python tests pass: complete release matrix, distribution commands,
  missing checksums, prerelease/untrusted URL rejection, failed/incomplete API
  fallback and static bilingual links/assets. Node checks cover reduced-motion
  precedence and gallery wrap boundaries. Online build selected real release 1.3.4.
- Both rendered locales have canonical and en/ru/x-default alternates, localized
  metadata, real installer links and installation text in the HTML.
- Public EN/RU pages and 32 linked resources/download endpoints returned HTTP 200.
  Published `SHA256SUMS` matches the checked-in verified snapshot byte for byte.
- Initial EN assets: 479,462 bytes uncompressed; combined JavaScript: 50,325 bytes
  gzip. Russian hero image and HTML add approximately 9 KB. Both remain well below
  the 1.5 MB target. Additional gallery screens load on demand.
- Pinned skill files and subset font hashes verified; both fonts contain Latin
  and Cyrillic glyphs. Original skill, GSAP and font notices retained.

## Browser checks

Using the available in-app Chromium browser, both languages were checked at
360, 390, 768, 1440 and 1920 px. Document scroll width does not exceed its client
width at any tested size. Download actions remain visible in the first screen.

- Live route sequence and stable result; scenario selection and replay;
  motion switch produces an immediate static result, including an interrupted
  route sequence. System reduced-motion precedence is covered by the policy
  test and CSS/GSAP media queries; browser OS emulation was not available.
- Sound starts off on page load, enables only after the sound button, and stops
  immediately when disabled. Language switching retains the section hash.
- Gallery selection, arrow/Home/End keys, zoom dialog, Escape and focus return.
  Real Russian gallery images load on the public site. No console errors/warnings
  observed on the enhanced local or public site.
- Identical EN/RU HTML served with `script-src 'none'` confirms static navigation,
  screenshot links, all four downloads and native installation disclosures.
  JS-only controls are hidden; all three routing explanations remain available.
- Control screenshots: `test-results/website/{en,ru}-{width}.jpg`, responsive
  measurements in `responsive.json`, public link checks in `public-links.json`.
  These local QA artifacts are ignored by Git.

Review reference: [Vercel Web Interface Guidelines](https://vercel.com/design/guidelines).
The review covered keyboard/focus, mobile hit areas, motion, semantics, contrast,
overflow, native scrolling and progressive enhancement. The decorative glow was
constrained to remove horizontal overflow, and small controls received 44 px hit
areas. This is an implementation review, not a claim of a formal WCAG audit or
cross-browser/device certification.

Application source, installers and tag 1.3.4 remain unchanged. Tag still points to
`64cff2b4216b4378cd5c455532667b134f4f75b9`.
