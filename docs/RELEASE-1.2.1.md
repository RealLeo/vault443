# Vault 443 1.2.1

Background status and journal reads no longer disable controls or trigger the
import progress label. The startup-profile menu keeps its model, open state,
keyboard focus and unapplied selection while connection statistics refresh.

- Import preparation and commit have separate request states. Canceled or stale
  replies cannot restore a dismissed preview or open an unrelated error dialog.
- Boot settings block only during Apply. A removed selection is identified and
  requires an explicit replacement; a failed save keeps the user's choice.
- Journal polling updates records without flashing toolbar buttons. Empty pages
  leave the list untouched. Manual paging and clearing supersede older reads;
  a late response cannot restore cleared records or the previous profile's log.
- Service loss, timeouts and errors reset request states. Journal errors stay in
  the journal view, and user-entered import text survives service recovery.

The window remains 472 × 480 and supports English and Russian. This patch does
not change networking, protocol engines, storage or public D-Bus methods.

Packages update directly from 1.2.0. ARM64 remains a cross-build; the installed
workstation service and network were not changed during development. See the
[validation record](VALIDATION.md) for checks and remaining platform limits.
