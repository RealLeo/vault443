# Vault 443 landing design

The website is an operating console for a real Linux desktop application.
Fallout 1–2's pre-rendered industrial hardware guides the materials: quiet worn
steel, tactile brass, recessed displays and practical hardware labels.

## Tokens

- Graphite `#1B1E1A`; steel `#42483F`; brass `#B59A61`.
- Phosphor `#A8C871`; ivory `#DDD2AD`; signal `#AD563D`.
- Roboto Condensed for headings and prose; a renamed, subsetted Iosevka for
  controls and terminal readouts. Both include Latin and Cyrillic.
- Maximum page width 1280 px; readable prose under 65 characters per line.
  Main text and headings are left aligned. The real application screenshot is
  centered in its monitor. Mobile follows the same reading order in one column.

## Composition

```text
┌ emblem / nameplate ─ navigation ─ motion / sound / EN RU ┐
│                                                        │
│ Your VPNs.                 ┌ tactile CRT frame ───────┐ │
│ One control panel.         │ real application image  │ │
│ positioning / downloads    │ startup sweep / LEDs    │ │
│                            └────────────────────────┘ │
├ profile support ─ work networks ─ clear diagnostics ──┤
│ scenario selector / lever  │ interactive routing CRT   │
│ screenshot selector       │ large real screenshot      │
│ distribution console / install commands / checksums    │
│ three setup steps         │ practical FAQ              │
└ source / license / docs / issues / release ─────────────┘
```

A centered poster was considered; the split console gives useful copy and the
actual application equal weight while leaving downloads available immediately.
The hardware carries the distinctive treatment. Supporting sections use clear
rules and recessed surfaces instead of repeating identical feature cards.

## Motion and interaction

One short CRT power-up sequence establishes the atmosphere. All further motion
responds to a visitor or introduces a specific console section. Routing is an
explicit simulation, never a browser VPN or a performance claim. Sound starts
off and uses brief synthesized clicks only after opt-in. Reduced motion and the
motion switch preserve the complete static experience. Scrolling stays native.

## Asset provenance

`prompts.json` contains the exact prompts used with built-in imagegen.
`manifest.json` records generated originals and optimized WebP derivatives.
The existing Vault 443 emblem and demo screenshots retain their original role.
Text and real controls are HTML; the route schematic is original SVG.
