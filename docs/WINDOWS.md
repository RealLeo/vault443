# Windows x64

Vault 443 targets Windows 10 22H2 (build 19045) and Windows 11 on x64 hardware.
The Qt interface runs as the signed-in user. The VPN service runs as LocalSystem;
only the narrow administrative helper requests UAC. The application and installer are unsigned; `Vault 443` in their metadata is
not an Authenticode-verified UAC publisher. The build scripts do not publish a
release; publication is a separate verified release step.

The current release target is **1.3.5**. Its user-facing installation changes and
validation status are recorded in [RELEASE-1.3.5.md](RELEASE-1.3.5.md#validation).
The completed 1.3.4 R9 port acceptance remains a historical baseline in
[WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md](WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md).
Its VMs and SDK were deleted after acceptance; new native checks require a
temporary build/test environment.

## Build inputs

Use the version locks in `packaging/windows/`, rather than resolving a current
release during an ordinary build:

- existing project Go lock: 1.27.3, used to cross-build the five Go executables;
- fixed MSVC 2022 Build Tools 17.14.44, Windows SDK 10.0.26100;
- Qt 6.12.0 MSVC2022 x64, with the published QtBase CVE-2026-105924 fix;
- Inno Setup 7.1.1, producing a native x64 setup executable;
- Xray 26.9.30 and official signed Wintun 0.14.1;
- OpenVPN 2.6 Windows runtime with Wintun, pinned independently in
  `openvpn-lock.json` (OpenVPN 2.7 removed Wintun support).

SHA-256 identities cover the SDK/runtime archives and matching sources. The
build records the exact native compiler, SDK, QtCore DLL, CMake and Ninja identities
as well as linked Go module versions and module sums. Sources and dependency caches
stay under `/var/www/projects/windows` and the repository's ignored `.cache/`.

On the Linux host, from the repository root:

```sh
python3 scripts/windows/dependencies.py fetch
python3 scripts/windows/prepare_sdk.py
python3 scripts/windows/openvpn_runtime.py stage
python3 scripts/windows/build.py backend
python3 scripts/windows/build.py stage
```

The dependency downloader resumes bounded transfers; rerun it if an archive is
still partial. Normal builds use the existing sealed locks. Refreshing a version
is a separate, explicit change to the corresponding lock and license sources.

The VM scripts use a private VirtualBox registry at
`/var/www/projects/windows/virtualbox`. They must run outside the restricted
sandbox; even a sandboxed `VBoxManage --help` can disrupt VirtualBox IPC. Existing
host VPNs and host networking must remain untouched. Run Windows VMs sequentially.

## Native build

The native build script is `scripts/windows/native-build.ps1`. The prepared build
VM uses these directories:

| Purpose | Path |
|---|---|
| MSVC | `C:\Vault443BuildTools` |
| Qt/Python SDK | `C:\Vault443SDK` |
| Sources, build trees, logs and payload | `C:\Vault443Build` |
| Host exchange copied through Guest Control | `C:\Users\Public\Vault443Exchange` |
| Inno compiler | `C:\Vault443Inno\ISCC.exe` |

Do not mistake an existing partially extracted SDK directory for a complete one:
completion markers are written only after successful extraction. Build QtCore
from the patched QtBase sources, deploy that DLL and import library into the Qt
SDK, then build the interface and run `windeployqt` against `ui/qml`.

The final runtime stage must contain the GUI, service and helpers, Xray, Qt/QML
plugins, official Wintun, all six protocol engines and required MSVC runtime DLLs.
The OpenVPN runtime is below `openvpn/`; its Wintun DLL must have the same identity
as the official DLL at the application root. Do not copy system DLLs from Windows.

Record native build identities in a UTF-8 JSON file, for example
`C:\Vault443Build\native-toolchain.json`. Required fields are:

```json
{
  "msvc": { "installationVersion": "17.14.37827.9", "compilerVersion": "actual cl.exe version" },
  "windowsSdk": "actual installed SDK version",
  "qtVersion": "6.12.0",
  "qtBasePatchSha256": "c27d27b86aaf2cdab0c18d513fbb94a432e98782eddfc5f856387e4be68be50b",
  "qtCoreSha256": "SHA-256 of the rebuilt and deployed Qt6Core.dll",
  "cmake": "actual CMake version",
  "ninja": "actual Ninja version"
}
```

## Notices and corresponding sources

After the **final** backend build, run on the Linux host:

```sh
python3 scripts/windows/licenses.py \
  --stage /var/www/projects/windows/license-stage --fetch
```

This collects notices for the exact linked Go dependencies, verifying each h1 sum
against the locked binary's BuildInfo, and bundles the matching Qt and Xray
sources, QtBase patch, upstream Qt SPDX metadata, fonts and runtime license texts.
The optional download mode fetches only missing locked inputs. Subsequent runs can
omit `--fetch` for offline collection.

Merge the resulting `licenses/` and bilingual `INSTALLATION-*.txt` into the native
runtime stage. Preserve the OpenVPN agent's `openvpn/` runtime, licenses and matching
sources. OpenSSL/LZ4 source notices added by the collector are in
`licenses/openvpn-additional/`. Copy Microsoft's applicable VC runtime redistribution
terms from the native toolchain into `stage/licenses/msvc/`; this is checked before
packaging. The license collector must be rerun if any project Go executable changes.

For a repeatable extraction of the runtime terms, obtain `VC_redist.x64.exe`
from the pinned native installation's `C:\ProgramData\Microsoft\VisualStudio\Packages`
cache. Record its FileVersion, SHA-256 and valid Microsoft Authenticode signature
in the native receipt, then copy it to the Linux build host and run:

```sh
python3 scripts/windows/msvc_licenses.py \
  --redistributable /path/to/VC_redist.x64.exe \
  --expected-sha256 SHA256_FROM_NATIVE_RECEIPT \
  --stage /var/www/projects/windows/license-stage
```

This uses `cabextract` to authenticate the EN/RU EULAs against the bundle's Burn
manifest and records their provenance. Merge this stage after `licenses.py`;
the redistributable itself is not included in the application payload.

Qt is dynamically linked. Interface-compatible modified Qt DLLs can replace the
installed DLLs, with administrator access to the protected installation folder. Qt source archives,
the exact patch and `licenses/qt/RELINKING.txt` accompany the distribution. No
static Qt linking or application signature check prevents such replacement.

## Compile the installer

Run the packager in Windows using the pinned embedded Python, supplying the exact
source ZIP created by `build.py stage` and the native toolchain JSON:

```powershell
C:\Vault443SDK\Python\python.exe C:\Vault443Build\source\scripts\windows\package.py compile `
  --stage C:\Vault443Build\stage `
  --source C:\Users\Public\Vault443Exchange\source.zip `
  --toolchain C:\Vault443Build\native-toolchain.json `
  --output C:\Vault443Build\dist `
  --iscc C:\Vault443Inno\ISCC.exe
```

The packager rejects missing runtime files, non-x64 DLLs/executables, mismatched
Go binary identities, an unpatched/replaced QtCore DLL identity, missing notices
or a substituted Wintun DLL before invoking ISCC. The Inno definition can also be
compiled directly for diagnosis:

```powershell
C:\Vault443Inno\ISCC.exe /Qp /DStageDir=C:\Vault443Build\stage `
  /DOutputDir=C:\Vault443Build\dist /DAppVersion=1.3.5 `
  C:\Vault443Build\source\packaging\windows\vault443.iss
```

`package.py prepare` validates/writes `build-manifest.json` without compiling;
`finish` writes artifact hashes after an independently successful ISCC invocation.
The output contains the setup EXE, SHA256SUMS, build/artifact manifests and exact
source ZIP. `artifact-manifest.json` deliberately records acceptance as `pending`:
the installer must still pass the matrix below. No signing or publishing occurs.
File timestamps are excluded from Inno payload entries for repeatability; preserve
the source ZIP, locks and native toolchain manifest when comparing rebuilds.

The locked `github.com/tailscale/wf` module has a reviewed local replacement in
`third_party/wf`, preserving its BSD license. The patch corrects the native
`FWPM_FILTER0` context union and aligns native arena allocations for Go's write
barrier. `packaging/windows/wf-patch.json` records the upstream version/h1, original
and patched source hashes and patch identity. Backend builds verify that source
tree; notices include the complete patched sources and patch proof. Packaging
rejects mismatches between that proof, its source payload and the backend manifest.
Other unreviewed Go replacements remain rejected. Native SDK offsets can be
checked without elevation using `tests/windows/wfp-abi.cpp`; the focused Go tests
are in `third_party/wf/vault443_abi_windows_test.go`.

The service retains the main Wintun creator handle across engine restarts and
disconnects. After a service crash, only an exact private GUID/name/Wintun identity
in Down, NotPresent or LowerLayerDown state may reach the official `CreateAdapter`
API; an Up or ambiguous existing adapter is refused and never adopted through
`OpenAdapter`. Wintun 0.14.1 performs its own driver-wide orphan housekeeping:
healthy foreign devices are skipped, while problem devices are not scoped to
Vault 443 by the vendor. The application does not issue manual PnP deletion or
rotate the main GUID to recover this state. See the pinned
[Wintun API implementation](https://raw.githubusercontent.com/WireGuard/wintun/0.14.1/api/adapter.c).

## Install, update and remove

Run the setup executable as the ordinary user and approve its UAC request. The
fresh-install destination page permits a local disk and folder, including spaces
and Unicode, with `{autopf}\Vault443` as the default. The installer validates the
path and protects application-owned files before installing or executing the
LocalSystem payload. Network destinations, reparse points and unsafe parent
ACLs are refused; unrelated parent directories are not re-permissioned. An
upgrade retains its registered installation folder. To relocate, uninstall while
retaining profiles, then install at the new location.

Setup starts the LocalSystem service and enrolls the active console user using
the helper's Windows token checks. The service creates its own private
`%ProgramData%\Vault443` storage, independently of the chosen application folder;
the installer never grants ordinary users access to that storage.

The GUI has a native PE icon and version resource from
`packaging/windows/vault443.rc.in`. CompanyName is `Vault 443`; product/file
versions come from `VERSION` through CMake. The committed multi-size
`packaging/windows/vault443.ico` is derived from the existing vault-door emblem
with `python3 scripts/windows/prepare_icon.py` (Pillow 10.2.0); native builds do
not need Pillow. Inno uses the same icon and publisher. These metadata fields
are separate from signing, and the application remains unsigned.

An upgrade stops the old service without clearing connection/boot intent or the
persistent guard, replaces the runtime, updates SCM and starts the service again.
A failed stop prevents file replacement. A failure to start the new service retains
files and profiles and returns installer exit code 10; user-enrollment failure
returns 11. The installer enrolls the console user only when its own process is
in that same active interactive session. SYSTEM unattended install/upgrade in
session 0 skips enrollment even if a console user is logged in; a successful
service installation therefore does not return enrollment error 11. The user's
first application launch requests UAC-assisted authorization if needed. Pipe
authentication and token/session checks remain in force.

Remove the application through Windows installed apps. Before any file deletion,
the uninstaller runs the LocalSystem maintenance path to release owned routes, DNS,
WFP filters and managed tunnels. If cleanup fails, uninstallation aborts and retains
files so the operation can be retried. Profiles and journals in ProgramData remain
by default. Foreign network resources are not removed. Exact application-owned
Run entries in loaded user registry hives are removed; unrelated entries remain.

For unattended VM acceptance:

```powershell
Start-Process .\Vault443-1.3.5-windows-x64-setup.exe `
  -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=C:\Vault443QA\install.log' -Wait -PassThru
Start-Process 'C:\Program Files\Vault443\unins000.exe' `
  -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=C:\Vault443QA\uninstall.log' -Wait -PassThru
```

Inspect the process exit code and actual service/network state. Installer success
alone does not prove that a protocol, handshake or leak protection works.

## External Windows VPN bindings

Administrator bindings enroll a present VPN adapter by its Windows GUID. The
public fields remain `interface`, `manager`, `unit`, `routes`, `dnsServers`,
`dnsDomains` and `endpoints`; `unit` is a Windows service name. A Linux `cgroup`
or packet mark is rejected. Corporate routes must be specific CIDRs; DNS domains
use the same normalization as work profiles. The binding alone never grants a
physical transport exception. Such exceptions additionally require a protected
LocalSystem VPN service and an identified protected transport process. Optional
`sourcePort` is supported for UDP after checking the native owner table.

Automatic enrollment is limited to the conventional official WireGuard tunnel
service, a protected executable/configuration, matching adapter identity, the
installed protected `wg.exe` public status, and a matching kernel UDP owner/port.
No private-key query is used. Ambiguous adapters are displayed without exceptions
and can be bound explicitly by an administrator. Pritunl/OpenVPN and other
supported service arrangements use explicit bindings.

Disappearing bound adapters retain specific corporate route and DNS protection.
A detected full tunnel pauses the main VPN; its temporary default DNS claim ends
when it becomes inactive, allowing the main VPN to resume. The coordinator owns
only its endpoint/DNS host routes and WFP/DNS plans. It does not delete routes or
configuration belonging to the external client. Bindings survive maintenance and
can be removed explicitly through the privileged binding operation.

## Acceptance gate

Use clean Windows 10 22H2 and Windows 11 25H2 snapshots without development tools,
plus the isolated Linux VPN fixture. Guest Control must remain available while the
network is blocked. Record logs, screenshots and pcap with timestamps.

- Install, update, remove; service identity and recovery; UAC; boot reconnect;
  restart/crash of the service and each engine.
- Real VLESS, Trojan, Shadowsocks/Outline, OpenVPN, WireGuard and AmneziaWG;
  imports/subscriptions, profile switching, traffic and redacted journals.
- Main/work VPN combinations; conflicting LAN/container routes; manual route
  priority; split DNS; full work tunnel main pause; partial peer failure.
- IPv4/IPv6, TCP/UDP/DNS; no direct packet leaks during connect, link changes,
  engine failure and service restart; exact cleanup on explicit disconnect.
- Two users, private profile isolation, unauthorized IPC/admin requests,
  authenticated named pipe and user authorization after switching sessions.
- Russian/English at 100%, 150%, 200%; tray, close-to-tray, single instance,
  autostart and file dialogs; Linux unit/integration/UI regressions.

An installer is ready only after the full matrix passes on both Windows versions.
Keep the final installer and evidence in `dist/windows/`, with SHA-256, build
manifest, instructions and acceptance report. For the 1.3.5 maintenance release, record the new installer/path/icon checks
separately from the historical full-port matrix: both OSes, standard and custom
paths, another local disk, Unicode, unsafe-path refusal, 1.3.4 upgrade, boot,
reinstall/removal, all six protocol families from the custom path, and EN/RU at
100/150/200%. After retaining artifacts and evidence, remove the temporary VMs,
ISO files, SDK and intermediate build data.
