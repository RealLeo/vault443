# Vault 443 1.3.1

Security and reliability fixes following an independent code review. The window
remains 472 × 480, with the existing English/Russian interface and artwork.

- **One locked compiler:** Go 1.27.3 builds the supervisor, Outline adapter and
  AmneziaWG for both architectures. Official archive hashes live in
  `packaging/go-toolchain-lock.json`; system Go is unchanged. Packaging inspects
  actual binary build metadata and requires a fresh passing vulnerability scan.
- **Safe switching:** preparation of B leaves confirmed A running. A guarded TUN
  replacement follows preparation; B is committed only after DNS/HTTPS health
  checks and durable intent storage. A failed candidate restores A and preserves
  its logical traffic session. Cancel B restores A; Disconnect cancels the main
  session entirely. Work VPNs remain independent.
- **Outline TCP half-close:** the SOCKS wrapper forwards `CloseWrite`, keeping the
  opposite direction usable until completion and releasing connection slots.
- **Outline alternatives:** selection considers the complete TCP/UDP graph and
  final backend. Simple SS2022 alternatives can use Xray; unsupported extended
  combinations are skipped. Selection preserves order and stops after at most
  256 complete configurations, with existing document/chain limits retained.

Additional issues uncovered by regression checks: a full ordinary journal queue
now drops excess messages before expensive processing (reserved failure records
remain independent); asynchronous source refresh returns the documented JSON
operation acknowledgement instead of triggering a false GUI response error.

## Upgrade

Use the normal package upgrade from **1.3.0**. Main storage remains v3 and work
storage remains v2; no migration or protocol source update is introduced.
Xray 26.9.30, Outline SDK v0.1.0-rc1 and AmneziaWG v3.1.20260828 stay pinned.

See [switch semantics](proxy-protocols.md#switching-main-profiles-safely), the
[extended D-Bus contract](interfaces.md#transactional-main-profile-switching-131)
and [validation](VALIDATION.md). Packages are built for amd64 and arm64; ARM64
remains a cross-build pending device acceptance. Nothing is installed, committed
or published by the release preparation workflow.
