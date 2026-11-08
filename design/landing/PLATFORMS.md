# Windows / Linux landing selection — 1.3.5

The same EN/RU URLs and original console composition serve both platforms.
`platform.js` runs before CSS, selecting a valid URL parameter, otherwise an
explicitly saved manual choice, otherwise a desktop OS hint. Mobile/unsupported
OS hints get the general view. All content and six real downloads exist in HTML;
without JavaScript the selectors are native links and both panels remain visible.
No visitor GitHub API requests or OS/architecture permission prompts are used.

The hero's English lead/download rectangles use the existing cleaned source,
recorded in the atlas manifest. Other hardware and original source references
are unchanged. Windows uses the existing nine-slice steel/brass frames, the
shared metal material and a native SVG mark. The Linux four-row atlas is retained;
Ubuntu 24.04 ARM64 is an additional native plate beneath it. Current screenshots
are explicitly identified as the Linux application with demo profiles.

## Release inputs

All six published 1.3.5 installer streams were hashed and matched against their
individual SHA-256 files, SHA256SUMS and GitHub asset digests. The receipt is
`website/data/release-verification.json`. The offline snapshot is 1.3.5; incomplete
or unreachable later releases fall back as one complete set, never mixed versions.
Installers, application APIs, services and release tags are not changed by this work.

## Acceptance

- 14 Python checks plus the Node motion and platform suites pass. Platform tests
  cover OS/mobile exclusions, URL precedence, saved preference, denied storage,
  both selectors, valid deep links, history and BFCache restoration.
- Live and offline builds both select 1.3.5. Maximum initial bytes: 1,339,906;
  JavaScript gzip: 54,306 bytes. These include platform CSS/JS and reused key frames.
- CUA checked EN/RU × Windows/Linux at 360, 390, 768, 1023, 1024, 1440 and 1920 px:
  no document overflow, new controls at least 44×44 CSS px, mobile zoom 1 and
  desktop zoom .75. Full-page reference captures and geometry are retained locally.
- Browser checks cover persisted manual choice, explicit URL override, language
  and section preservation, Back/Forward, gallery keyboard navigation, enlargement,
  Escape/focus return, PowerShell clipboard contents and native ARM64 instructions.
- CSP-disabled JavaScript leaves all six downloads and native instructions usable,
  with the door open. Missing GSAP still permits platform switching and gallery use.
- 27 unique external release/checksum/documentation links returned HTTP 200.
  Gallery, demo and platform content use native text; no installer was executed.

Local QA artifacts are under the ignored directory
`test-results/website-platform-1.3.5/` (`responsive.json`, `functional.json`,
`links.json` and screenshots). OS detection for unavailable OS/browser combinations
is covered by synthetic navigator inputs; the browser viewport matrix is real.
