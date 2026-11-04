# Vault door implementation

Approved references: reference-desktop.png (1487×1058), reference-mobile.png
(887×1774). Their geometry, dense metal construction and lighting are the target.

Palette: graphite #202527, blue steel #3d4548, aged brass #ba9858,
ivory #ddc79a, signal green #79df53, dark recess #0a100c.
Roboto Condensed 900 carries dense engraved headings and controls; existing
Roboto Condensed 400 handles prose and Vault Terminal handles readouts.

Desktop: connected chassis, 34% introduction / 66% vault assembly. The central
window uses real application screenshots. Mobile below 1024px: introduction and
download first, then the door, then six protocol plaques in two columns.
Frame, cylinder, cams, shutters and plates are individual imagegen bitmap layers.
Typography, lamps, interaction targets and pictograms remain native HTML/SVG.

The chosen design replaces the previous sparse split hero with a contiguous
heavy hardware interface. Large generic marketing headings and floating monitor
parallax are removed. All supporting sections continue the same physical chassis.

One 900 ms startup: cams 0–180 ms, shutters 120–720 ms, lamps/glow 300–900 ms.
Default HTML/CSS is already open. Motion disabled or missing GSAP always leaves
the open state. Downloads never depend on the boot sequence. Audio starts off.
