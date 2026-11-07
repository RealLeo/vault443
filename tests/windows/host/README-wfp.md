# Isolated Windows WFP acceptance tools

These Windows-only Go programs are QA artifacts, excluded from Linux package and
test discovery. They add no product CLI flags or services.

From the repository root, using the pinned Go toolchain:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 python3 scripts/go.py build ./tests/windows/host/...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 python3 scripts/go.py build -trimpath -o /tmp/vault443-wfp-foreign.exe ./tests/windows/host/wfp-foreign
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 python3 scripts/go.py test -trimpath -c -o /tmp/vault443-wfp-foreign.test.exe ./tests/windows/host/wfp-foreign
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 python3 scripts/go.py build -trimpath -o /tmp/vault443-wfp-inspect.exe ./tests/windows/host/wfp-inspect
```

Run the validation tests natively; they do not access WFP or change files:

```powershell
.\vault443-wfp-foreign.test.exe -test.run TestForeign -test.v
```

`wfp-foreign` requires explicit UAC elevation as the controller SID in the
protected `C:\ProgramData\Vault443-QA\qa-inputs.json`, the private QA marker, and
the named VirtualBox guest `VAULT443-WIN10` or `VAULT443-WIN11`. Existing Vault443
WFP provider and sublayer must be present, for example with main protection armed.

```powershell
.\vault443-wfp-foreign.exe setup
# Controller performs the separate service restart / uninstall-abort test.
.\vault443-wfp-foreign.exe cleanup
```

Setup creates exactly one persistent BLOCK rule for TCP `198.51.100.254:9`, weight
1, with a random GUID outside the application's ownership journal. Its private
recovery identity is atomically saved in `Vault443-QA\foreign-reference.json`
before AddRule. Cleanup checks the complete expected rule identity and conditions
inside a WFP transaction, deletes only that GUID, and then removes its own journal.
Changed fields cause refusal; preserve the journal until successful cleanup. No
VPN stores, containers, routes, services, or network configuration are changed.
Output contains only mode, fixture rule GUID, and result. The fixture uses normal
filter enumeration and refuses operation if the existing provider is disabled.

`wfp-inspect` is read-only and can be run elevated for access to all WFP objects:

```powershell
.\vault443-wfp-inspect.exe
```

It reports the exact provider ServiceName/Persistent/Disabled and filter counts
for Vault443's six ALE connect/receive and outbound boot layers. Enumeration
explicitly includes boot-time and disabled filters. It does not expose other
providers, rule conditions, or VPN data. ServiceName documentation is inconsistent
between Microsoft structure and object-management pages; actual boot behavior
must be established by native capture and inspection.

Checkpoint SHA-256, Go 1.27.3, `windows/amd64`, `CGO_ENABLED=0`, `-trimpath`:

| Artifact | SHA-256 |
| --- | --- |
| `vault443-wfp-foreign.exe` | `57f5e09a57d2c08b19fa93540f09416e9d1a949f7b544ba80bce4caa385edb68` |
| `vault443-wfp-foreign.test.exe` | `26a46865b84cefa75dcc61f607f0bcbde2f566bd9c2ea24ad5b252d3fd739c3b` |
| `vault443-wfp-inspect.exe` | `2e7249f620b8365ef9ec71c40a85f7884cf5a0c966446f219397a42391eba834` |

These identify this source/build checkpoint, not a signed release. Cross-build
passed; native execution of these repository-path builds is pending.
