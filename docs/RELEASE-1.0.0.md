# Vault 443 1.0.0

Historical baseline release: the VLESS Terminal application was renamed to
**Vault 443**, keeping its 472 × 480 Qt interface and pinned Xray 26.9.30 core.
It introduced service-owned session traffic accounting, rates and totals, and
new `vault443` package, service, group and D-Bus identifiers.

This release shipped a dedicated transition installer with private backups,
traffic protection, resume and rollback, plus per-user language/autostart
migration. Those tools belong to the **1.0.0 release artifacts**. They were
removed from the source tree in 1.0.1 after the transition was completed.
Existing system backups are not removed by subsequent releases.

The current project supports fresh installs and updates from Vault 443 1.0.0.
See [the README](../README.md) for current installation instructions and
[validation](VALIDATION.md) for the limits of the tested environments.
