# Vault 443 1.3.3

Arrange main and work VPN profiles together in any order. Drag the six-dot brass
handle between the emblem and screen, or focus it and press **Ctrl+↑ / Ctrl+↓**.
A translucent card and insertion line show the destination; dropping commits the
move. Holding near an edge scrolls the list. Escape, an outside drop, hiding the
window or losing the pointer grab cancels the gesture.

- The order belongs to the desktop user and survives interface restarts. New
  profiles append at the end. Renaming, reconnecting and background updates keep
  their positions. An unwritable preference file rejects the move with an error.
- A stable Qt item model updates individual cards without rebuilding the list.
  A library membership change cancels an in-progress drag; loss of the service
  preserves the last library and saved order.
- The main list has a permanently visible, narrow olive/brass scrollbar inside
  the right metal frame. Its wider hit area supports thumb dragging and page
  clicks. Empty and short lists retain a subdued track and stationary thumb.

The 472×480 layout, English/Russian UI, service API, profile stores, tray ordering
and boot connection choice remain unchanged. Sorting sends no network commands.
Demo mode keeps its order in memory. The OpenVPN/NetworkManager fix from 1.3.2 is
retained, with unchanged Xray, AWG, Outline SDK and locked Go versions.

Packages: x86-64 Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch Linux.
See [installation and checksums](linux-packages.md), [profile list behavior](profile-order.md)
and the [validation record](VALIDATION.md). ARM64 is not part of this release.
Container tests share the host kernel; physical desktop and Fedora enforcing
SELinux acceptance remain separate. Development does not install the application
or switch the workstation's network.
