# Vault 443 1.0.1

The traffic panel now keeps session duration, download/upload speed and
session download/upload totals on **one line**, within the existing 472 × 480
window. Fixed-width fields prevent values from moving their neighbors.
The original font sizes and panel height are retained. Units are localized,
include EB, and omit digit grouping; tooltips show the full byte amount.
Unavailable or private statistics still display dashes.

The service's accounting behavior and public D-Bus API are unchanged. Current
storage schema v2 is preserved. Unsupported schemas are rejected without
rewriting their files.

The source tree now targets **Vault 443 1.0.0 and later**. It no longer contains
the older client transition installer, per-user migration helper, v1 schema
conversion, unused import UI entrypoints, or 0.2.x release material. Direct
installation over an old client or pending migration is still refused before
changing its data. Complete that transition with the 1.0.0 release tools first.

Unused font weights and image slices were removed. Qt resources are listed
explicitly; source artwork, original concept, prompts and licenses remain.
Generated reports, screenshots and build products stay outside the publishable
source tree. README images were refreshed using fictional English demo data.

Install or update from the repository root:

```sh
sudo apt install ./dist/vault443_1.0.1_amd64.deb
```

Artifacts: `vault443_1.0.1_amd64.deb`, `vault443_1.0.1_arm64.deb` and SHA-256
checksums. ARM64 is cross-compiled and still needs device acceptance. Xray stays
at pinned **26.9.30 (prerelease)**. See [validation](VALIDATION.md).
