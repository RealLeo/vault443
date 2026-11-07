# External OpenVPN ownership fixture

This is a test-only SCM wrapper, never part of `dist/windows` or a shipping
stage. It operates only as `LocalSystem` in the named `vault443-win10` and
`vault443-win11` acceptance guests with the privileged QA bootstrap marker
`C:\ProgramData\Vault443-QA\marker` containing
`Vault443 isolated Windows fixture`. The setup does not create that marker. No VM
operations are performed by these files.

Cross-build from the repository root with the pinned project Go toolchain:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -trimpath \
  -o /tmp/vault443-external-openvpn.exe ./tests/windows/external-openvpn-service
```

The root acceptance controller copies that executable to
`C:\Users\Public\Vault443Exchange`. Keep the temporary profile and private key
in the QA user's private directory. Run `setup.ps1` explicitly elevated in
the guest, optionally with `-FullTunnel` and `-ProfilePath <private-profile>`.
The default profile is `%LOCALAPPDATA%\Vault443\qa-ui-import\fixture-openvpn.ovpn`;
do not stage its credential material in Public. Setup creates private SYSTEM/admin
directories, reconstructs a fixed safe client configuration using only the
three inline PEM blocks, installs a manual service, and leaves it stopped.
No imported directives, executable paths, scripts or plugins are retained.

Installed image: `C:\Program Files\Vault443ExternalFixture\vault443-external-openvpn.exe`.
Configuration/logs: `C:\ProgramData\Vault443ExternalFixture`.
Engine: the installed protected `C:\Program Files\Vault443\openvpn\openvpn.exe`
(pinned OpenVPN 2.6.23), with the application's signed Wintun DLL.
Adapter: `corp-external`. Service: `CorpExternalOpenVPNFixture`.
The test adapter uses the `OpenVPN Wintun` tunnel type so normal VPN discovery
recognizes its driver description; service/worker ownership still requires the
separate administrator binding.
The built-in OpenVPN work fixture must be disconnected first because the same
temporary client certificate is reused.

The acceptance controller starts/stops the SCM service and creates the explicit
administrator VPN binding separately. Verify the real adapter GUID, LocalSystem
service/worker ownership, UDP endpoint, protected routes and split DNS; then
check full-tunnel pause/resume while the main VPN is requested. Installation
alone makes no VPN connection and creates no binding or protection exception.

SCM stop sets a private, per-start manual-reset global event. The official
OpenVPN `--service exit-event 0` monitors that event and performs normal shutdown
when signaled. The wrapper waits 20 seconds before Job Object fallback; it holds
the Wintun creator handle until the child has stopped. This behavior follows
the pinned official source `doc/man-sections/windows-options.rst` (`--service`)
and `src/openvpn/win32.c` (`win32_signal_open`, `win32_signal_get`):
https://github.com/OpenVPN/openvpn/tree/v2.6.23

Cleanup: run `setup.ps1 -Uninstall` explicitly elevated. It stops/deletes only
the fixed service and retains configuration/logs. After evidence collection,
the controller may remove the two dedicated fixture directories. No application
profiles, application service, driver installation or unrelated adapters are
removed.
