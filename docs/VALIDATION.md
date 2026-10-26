# Validation

Current release: **Vault 443 1.0.1**. Runtime network and package tests use
network-isolated disposable containers. The developer workstation's installed
VPN service and active network are not switched by this work.

## Release checks

Completed on 26 October 2026:

- Qt English/Russian interactions, single-line fixed-width traffic layout,
  large values, absent service, foreign sessions and private D-Bus operations.
- X11/Wayland in isolated Xvfb/Weston at 100/125/150/200%, English and Russian,
  on Ubuntu 24.04 (Qt 6.4.2) and 26.04 (Qt 6.10.2). QtTest is compiled for each
  runtime; production screenshots use the same Qt 6.4 application binary.
- Go race/vet, storage v2 preservation, and rejection of unsupported schemas
  without rewriting their source documents.
- Real systemd package installation and 1.0.0 → 1.0.1 upgrade on Ubuntu 24.04 and
  26.04, with an active local VLESS connection, retained multiuser state,
  subscriptions, boot selection, GID, and unrelated firewall rules. A physical
  bypass monitor runs throughout the active upgrade.
- Reinstallation, removal, fresh APT install, refusal of the old client/pending
  transition, and retention of completed private recovery backups.
- Build from the publishable 220-file source set (about 57 MiB), with exact
  regeneration of all 14 skin slices and 20 emblems; explicit asset references,
  README links/images, no generated binaries or private state in that set.
- amd64 and ARM64 package metadata, version, executable architecture, checksums
  and absence of development-library RPATHs.

The final native Qt suites and private D-Bus cases pass on both languages;
Go race and vet pass. Artwork comparison confirms 705725 original pixels
unchanged outside the documented repairs. No Git repository was created.

Raw logs and screenshots are local generated artifacts under `test-results/`
and `.cache/v101/`, excluded from Git. Keep the release's summarized results here
instead of committing machine-specific command logs.

## Existing network regression coverage

The 1.0.0 baseline passed real TLS/REALITY, DNS/HTTPS bootstrap, UID isolation,
IPv4/IPv6 and Docker-forwarded protection, recovery after core/daemon failure,
NetworkManager connectivity reporting and actual TUN download/upload accounting
on Ubuntu 24.04 and 26.04 amd64 userspace. The 1.0.1 network policy, accounting
and public D-Bus contract are unchanged; its package upgrade exercises the real
connection and traffic guard again.

## Limits

Container tests share the host kernel and do not certify a physical GNOME
session, power loss during boot, real Pritunl deployment or an ARM64 device.
ARM64 is a cross-build. The Ubuntu 26.04 fixture may report an unrelated
netplan-configure failure without udev; NetworkManager, resolved and D-Bus are
checked explicitly. Xray remains pinned to **26.9.30 (prerelease)**.
