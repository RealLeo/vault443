# Vault 443 1.3.2

Managed OpenVPN full IPv4 tunnels now register with NetworkManager so the desktop
Internet indicator follows a real connectivity check through the VPN. Previously,
Internet worked through Vault 443's policy tables while NetworkManager reported
limited connectivity because it could not see a default route on the TUN.

- Reuse the main tunnel's registration mechanism with the real OpenVPN gateway
  and coordinator-selected DNS. Only the selected Internet owner registers.
- Serialize bounded background D-Bus requests, preserve external addresses/routes,
  validate generated/volatile profiles, and avoid reapplying unchanged settings.
- Remove the injected default on outages, cancellation and ownership changes,
  including persistent TUNs. Retain guarded destinations and corporate DNS.
- Reconcile after NM/service restarts and address changes; expose safe integration
  status in work diagnostics and profile journals.

Internet checks stay enabled. No physical-interface exception or fabricated FULL
state is introduced. The interface, dimensions, D-Bus signatures and store schemas
are unchanged. Xray, AWG, Outline SDK and the locked Go compiler are unchanged.

Packages: x86-64 Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch Linux.
See [installation and checksums](linux-packages.md) and the [validation record](VALIDATION.md).
No ARM64 build is included in this maintenance release. Container validation shares
the host kernel; physical-desktop and Fedora enforcing SELinux acceptance remain
separate. Development and tests do not install or switch the workstation VPN.

Reproduce the focused network regression in an isolated NM-enabled image:

```sh
VAULT443_E2E_NM=1 VAULT443_E2E_IMAGE=vault443-nm:24.04 \
  VAULT443_E2E_TEST_PATTERN='^TestRealOpenVPNNetworkManager' \
  bash scripts/test-wireguard.sh 24.04
```

The test runner creates a network-none disposable container with synthetic keys;
it never connects to a real corporate endpoint.
