# Vault 443 1.3.4

Profile drag handles are now three vertical brass dots to the left of each VPN
emblem. They fit the existing left strip with a transparent 14×32 logical-pixel
hit area at the default scale, without moving the emblem, screen or buttons.

- No handle frame, background, focus outline or hover tooltip. Hover changes only
  the cursor to an open hand; dragging uses a closed hand. A single profile's
  handle stays subdued and inactive.
- Remove Ctrl+Up/Down reordering and its shortcut hints. Handles do not enter the
  Tab sequence or take keyboard focus when pressed. Their English/Russian
  accessible names remain available.
- Keep drag threshold, translucent preview, insertion line, edge scrolling,
  cancellation, per-user order persistence and the permanent themed scrollbar.
  Mouse reordering retains the viewport without moving focus to a handle.

The 472×480 layout, service API, stored profile IDs and network behavior are
unchanged. The OpenVPN/NetworkManager fixes from 1.3.2 and stable-list behavior
from 1.3.3 are retained. Xray, AWG, Outline SDK and locked Go are unchanged.

Packages: x86-64 Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch Linux.
See [installation and checksums](linux-packages.md), [profile ordering](profile-order.md)
and the [validation record](VALIDATION.md). Container tests share the host kernel;
physical desktop and Fedora enforcing SELinux acceptance remain separate.
Development does not install the application or switch the workstation's network.
