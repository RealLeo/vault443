# Vault 443 website

English lives at `/vault443/`, Russian at `/vault443/ru/`. A Python standard-library
builder renders both from one template and equivalent translation dictionaries.
No visitor API requests, trackers, accounts, build framework or backend.

```sh
python3 -m unittest discover -s website/tests -v
node website/tests/motion.cjs
python3 website/build.py --offline
python3 website/tools/serve.py
```

Open `http://127.0.0.1:8443/vault443/`. Without `--offline`, the build obtains the
latest stable GitHub release. It requires exactly one matching installer for each
of four distributions, individual `.sha256` assets and `SHA256SUMS`. An unavailable
API or incomplete release falls back to the verified 1.3.4 snapshot, displaying
1.3.4 rather than pretending to have the latest version. Refresh the snapshot only
after checking downloaded installers against the published checksums. Files and
shell commands are rendered into HTML; downloading works with JavaScript disabled.

`assets/` is deployable input; `dist/` is generated and ignored. Keep images and
fonts prebuilt so CI only needs Python. GSAP 3.15.1 is vendored with its original
license notices and NPM SHA-512 integrity in `assets/vendor/source.json`.
The GSAP runtime uses its Standard No Charge License; the development skills have
their own MIT/Apache licenses. Do not conflate them. Font licenses and subset
hashes live in `assets/fonts/`. Generated image originals, prompts and production
hashes live in `../design/landing/`; optimized WebP files live in `assets/generated/`.

The native English demo screenshots come from `docs/images/readme/`. Russian
screenshots were captured with the same manifest and `LANGUAGE=ru` using the
application's real `--demo --screenshot` path. Do not replace them with mock UI.

The build enforces a 1.5 MB initial uncompressed asset budget and 100 KB compressed
JavaScript budget. Gallery screens are lazy loaded. Preserve progressive
enhancement, keyboard access, static reduced-motion states and audio opt-in.

The vault-door redesign uses `templates/hero.html` and a final `assets/vault.css`
hardware layer over the existing section layout. Its approved desktop/mobile
references, six imagegen source PNGs, exact prompts, optimized hashes and font
source are under `../design/landing/vault-door/`. Production art is `assets/vault/`.
Roboto Condensed 900 is pinned to Google Fonts commit
`69d0549e8fc7ad72e1531734c81237be401ec4fd`, version 3.008, OFL-1.1.
The pre-existing regular face keeps its separate Apache 2.0 license.

The door starts in the accessible open state. Enhancement adds a 900 ms sequence:
cams 0–180 ms, shutters 120–720 ms, lamps/glow 300–900 ms. A session flag prevents
automatic replay when changing language. The status rail offers manual replay,
motion and sound; stopping motion settles open immediately. There is no autoplay
audio. `node website/tests/motion.cjs` checks lifecycle interruption and storage
failure as well as policy and gallery boundaries.

The builder counts all new artwork, both CSS layers, fonts and the larger of
EN/RU entry documents/screens. It writes `dist/budgets.json`. Local fallback QA:

```sh
python3 website/tools/serve.py --port 8766 --no-js
python3 website/tools/serve.py --port 8767 --no-gsap
```

Publication uses `.github/workflows/pages.yml` and the repository's Pages source
must be **GitHub Actions**. Actions are pinned by full commit in the workflow and
recorded in `data/action-pins.json`. The workflow reacts to website changes on main,
published/edited releases and manual dispatch. It does not change app packages/tags.

Design review reference: [Vercel Web Interface Guidelines](https://vercel.com/design/guidelines).
Pages reference: [GitHub custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
