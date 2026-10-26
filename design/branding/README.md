# Vault 443 skin update

The original approved concept remains unchanged in `../reference/concept.png`.
`vault443-generated.png` was edited with the built-in imagegen tool using
[`prompt.txt`](prompt.txt). It supplies only the nameplate interior and the blank
statistics CRT surface. The title is **VAULT 443**.

`scripts/extract-skin.py` resizes the generated sheet to the 944×960 source window
and copies only two recorded interior rectangles. Existing frames, bolts, cards,
and casing remain source pixels. `assets/skin/manifest.json` records both input
hashes and all allowed repair rectangles; `scripts/verify-skin.py` checks the
retained pixels. Dynamic time, arrows, rates and totals are QML text.
