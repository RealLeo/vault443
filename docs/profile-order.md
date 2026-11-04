# Profile order and scrolling

Drag the three vertical brass dots to the left of an emblem to choose where a profile appears.
VLESS, Trojan, Shadowsocks/Outline, OpenVPN, WireGuard and AmneziaWG can be mixed.
Emblems still open properties, status text opens diagnostics, and connection
buttons retain their actions. Dragging starts after the desktop's normal movement
threshold. Release inside the list to save the destination; Escape, releasing
outside, hiding/deactivating the window or losing the grab cancels. Hold near
either edge for automatic scrolling.

The borderless handle has no background, focus outline or tooltip. Its transparent
hit area is 14×32 logical pixels at scale 0.5 and does not overlap the emblem.
Hover shows an open hand, dragging a closed hand. It does not take keyboard focus
or enter the Tab sequence; Ctrl+arrow keys do not reorder profiles. A single
profile's handle stays subdued and disabled. The scrollbar in the main frame
supports dragging, page clicks, mouse wheels and touchpads. Other windows keep
their existing scrollbars. Its visible width is 3 logical pixels, hit area 10,
and minimum thumb length 24 at the default 0.5 scale.

The GUI saves IDs under `ui/profileOrder` in the current user's `QSettings`
(`~/.config/Vault443/vault443.conf` with default XDG paths). No root access or
D-Bus mutation is involved. A stable `ProfileListModel` uses row insert/remove/move
notifications and per-row data updates; active connection, boot profile and tray
order stay with the service's snapshot. Missing or malformed preferences start
with the service's order; duplicate/unknown IDs are ignored. New profiles append.
Only a complete successful library snapshot removes deleted IDs; an unavailable
service does not clear the order. An unsuccessful preference write rejects a user
move before changing the model and displays a translated error.

Scroll position and focus are anchored to profile IDs. Runtime changes do not
rebuild the model or interrupt gestures. Adding/removing a profile cancels a
gesture before reconciling the library. Demo preferences remain in memory;
automated tests use temporary settings and synthetic profiles.
