# Profile emblem assets

Twenty separate icons were generated with the built-in imagegen tool on
2026-10-07, one call per icon, with actual transparent backgrounds. Exact prompts
are in `prompts.json`; the additional blank badge edit is recorded in
`blank-prompt.txt`. Full native PNG outputs are retained here unchanged.

Production textures in `assets/profile-icons/` are 256×256 RGBA PNGs, reduced
with Lanczos sampling. Their alpha is preserved. The UI displays each glyph in
an approximately 40×40 logical-pixel area at the default window scale. Resource
IDs and Russian labels are listed in `assets/profile-icons/catalog.json`.

The original antenna, dish and globe remain in `assets/skin/`. `blank.png` uses
the original 114×115 antenna badge frame with only its inner rectangle
`[17,18,99,100)` replaced by the corresponding area of the generated blank,
resampled to 114×115. All pixels outside that rectangle are unchanged.
This prevents either the old antenna or a regenerated frame from appearing
under a new glyph. The original reference and existing skin files are unchanged.

Reproduce the production textures with `python3 scripts/prepare-profile-icons.py`.
No image generation or network access occurs in that preparation step.
