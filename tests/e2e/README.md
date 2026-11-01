# Isolated VPN integration tests

These tests exercise the production `network.Manager` and pinned Xray binary with
real Linux TUN, nftables, policy routing, TLS and systemd-resolved. They run inside
a disposable Docker container with **no external network**. Ordinary `go test
./...` skips these tests.

The container creates a second network namespace for a private VLESS server,
HTTPS DNS responder and HTTP endpoint. TLS and REALITY/Vision have separate
inbounds; REALITY uses a fresh X25519 identity and the local HTTPS server as its
target. The runner generates a fresh CA and installs it
only in the container's trust store. Certificate verification stays enabled. The
addresses `1.1.1.1` and `93.184.215.14` are local aliases in this server namespace;
no requests go to the Internet. This preserves the production DoH configuration.

## Run

Requirements: Linux amd64, Go 1.22+, Docker, and TUN/netfilter support in the Docker
host kernel. Run these commands from the repository root. The repository and
pinned core are mounted read-only during the test. Only the selected results
directory is writable from the container.

```bash
python3 scripts/fetch-xray.py amd64
export GOMODCACHE="$PWD/.cache/go-mod"
export GOCACHE="$PWD/.cache/go-build"
CGO_ENABLED=0 python3 scripts/go.py build -buildvcs=false -o .cache/e2e-fixture ./tests/e2e/fixture
CGO_ENABLED=0 python3 scripts/go.py test -c -o .cache/e2e.test ./tests/e2e

for version in 24.04 26.04; do
  docker build --network=host --build-arg UBUNTU_VERSION="$version" \
    -t "vault443-e2e:$version" -f tests/e2e/Dockerfile tests/e2e
  results="$PWD/.cache/e2e-results-$version-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$results"
  docker run --rm --network none \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined --device /dev/net/tun \
    --env VAULT443_E2E_ISOLATED=1 --env VAULT443_SANDBOX_FILTER_ONLY=1 \
    --mount "type=bind,src=$PWD,dst=/src,readonly" \
    --mount "type=bind,src=$results,dst=/results" \
    "vault443-e2e:$version" /usr/bin/python3 /src/tests/service-sandbox-probe.py \
      /src/packaging/vault443.service /bin/bash /src/tests/e2e/entrypoint.sh
done
```

`--network=host` applies only to the image build, where apt downloads test tools;
it avoids Docker DNS issues behind an existing host VPN. Runtime must use
`--network none`. The entrypoint refuses to proceed unless it is in Docker and
its only initial interface is `lo`. Never invoke the entrypoint on the host, add
host networking to the runtime, or mount the host's `/etc`, `/run` or `/var/lib`.

`SYS_ADMIN` and the AppArmor override allow `ip netns` inside the disposable
container. They do not give the tests a host network namespace. The fixture and
test binaries are static Go binaries; the Ubuntu images provide the real distro
network tools and resolver.

## Managed work VPN fixture

Build the current daemon and test executable before the work run:

```sh
CGO_ENABLED=0 python3 scripts/go.py build -buildvcs=false -o build/vault443d ./cmd/vault443d
CGO_ENABLED=0 python3 scripts/go.py test -c -o .cache/workvpn-e2e.test ./tests/e2e
```

Use the same isolated container command above, adding these environment values:

```sh
--env VAULT443_WORKVPN_E2E=1 \
--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
--env VAULT443_E2E_TEST_BINARY=/src/.cache/workvpn-e2e.test \
--env VAULT443_E2E_TEST_PATTERN='^TestRealWorkVPN'
```

The opt-in fixture generates certificate-authenticated OpenVPN servers and client
profiles inside `/fixture`, a Docker-like bridge at `192.168.96.0/20`, and a work
HTTP endpoint at `192.168.100.15`. It checks both VLESS/work startup orders,
independent work destinations and split DNS, explicit route choices, conflicting
providers, full-tunnel pause/resume, cancellation protection and retained desired
connections after supervisor restart. It also exercises a Docker-like source
namespace and actual IPv6 work traffic; reverse-path filtering is not weakened.
Run this separately from the VLESS suite:
the latter deliberately rejects unexpected fixture interfaces.

The package PID1 runner additionally seeds generated work profiles while the
daemon is stopped and tests the installed hardened unit, event helper, two work
connections, crash recovery and removal. This does not relax production D-Bus
authorization. It requires the current `.cache/workvpn-e2e.test` and the prior
`dist/vault443_1.2.0_amd64.deb` upgrade baseline. All raw journals and captures stay
in ignored `test-results/` directories.

This runner also applies the packaged unit's seccomp syscall deny-list.
The E2E fixture retains its container capabilities for network namespace setup;
it does not emulate all systemd sandbox settings. The separate
`TestDiscoveryServiceCapabilities` test (run by `scripts/test-kernel.sh`) applies
each unit's exact capability bounding set and syscall filter to discovery of a
real OpenVPN TUN/socket. It checks that the old capabilities cannot identify the
peer and the corrected capabilities can, while debugging syscalls remain denied.

## WireGuard and AmneziaWG

Build the pinned AWG binary and run the dedicated fixture:

```sh
python3 scripts/build-amneziawg.py amd64
bash scripts/test-wireguard.sh 24.04
bash scripts/test-wireguard.sh 26.04
# A cached equivalent runtime image can be selected without downloading:
# VAULT443_E2E_IMAGE=vault443-test:24.04 bash scripts/test-wireguard.sh 24.04
```

The runner builds current fixture/daemon/test binaries, uses `--network none`,
and generates keys and PSKs only inside the container. Five endpoints exercise
kernel WireGuard plus AWG legacy, 2.0/CPS and 3.1, including multiple peers. Tests
cover IPv4/IPv6 endpoints and traffic, overlapping Docker destinations, split DNS,
full-tunnel VLESS pause, both startup orders, coexistence with OpenVPN, incorrect
PSK, no false connection without handshake, partial peer failure, cancellation,
idle key renewal, engine death and recovery. Explicit route rules outside
AllowedIPs are rejected without affecting an existing connection.

Results are in `test-results/<version>/wireguard-<release>/`. Set
`VAULT443_E2E_RESULTS` for another ignored results directory or
`VAULT443_E2E_TEST_PATTERN` for a focused run. The AWG health fixture shortens its
own rekey timers; production defaults are unchanged.

The package PID1 suite preserves work schema v2 across patch updates, verifies old
D-Bus signatures, then runs WG/AWG through the installed hardened service. It
checks recovery after SIGKILL (including a surviving kernel WG interface), normal
restart, continuous protection and purge. It never runs a host systemd command.

## Assertions

- the IPv6-exit regression blocks only outbound IPv6 web traffic
  in the private REALITY/Vision server namespace. A narrowly scoped temporary
  TUN allowance first reproduces the old failure: UID 1000 completes IPv6 TCP,
  then its verified TLS handshake fails. With the production policy restored,
  unavailable IPv6 is rejected before TCP acceptance, A/AAAA DNS answers remain
  intact, and an ordinary unmarked dual-stack HTTP/2 request reads a 704 KiB
  response over IPv4. The connection stays protected and direct physical
  bypass remains blocked. Restoring the exit and reconnecting enables IPv6;
  a later IPv6-only outage is detected by the real 30-second periodic check
  without disconnecting healthy IPv4. The test runs with both Ubuntu images.
- the web fixture also serves verified HTTPS and HTTP/2. Real
  unprivileged UID 1000 and root clients use normal unmarked sockets and the
  system resolver to exercise IPv4/IPv6, TLS 1.2/1.3, HTTP/1.1/2 and a 704 KiB
  payload with VLESS/TLS and REALITY/Vision Firefox.
- A separate regression blocks only web HTTPS while leaving Xray's internal
  DoH operational. The old DNS-only health check incorrectly returned Connected;
  the new one reports `vpn_https_timeout`, retains the guard and connects after
  HTTPS is restored. The connectivity endpoints are aliases of the private
  fixture; no external connectivity-check service is contacted by these tests.

- an isolated firewall blackholes DNS/53. A hostname-based
  connection falls back after two seconds to the fixed `1.1.1.1:443` address,
  validates `cloudflare-dns.com` with the fixture CA, resolves a public-looking
  core endpoint, and establishes real VLESS. NXDOMAIN, a canceled in-flight
  HTTPS request, and both transports unavailable preserve the guard and concrete
  error. Status and diagnostics stay readable throughout the operation.
- The bootstrap scenario uses the namespace's normal reverse-path filtering.
  Narrow root-UID routing hints allow valid resolver/core replies through Linux
  reverse lookups, while nftables still requires the private socket mark for
  outgoing physical traffic. No host or namespace sysctl weakening is needed.
  A separate `TestKernelBootstrapScopes` injects real IPv4/IPv6 forwarded TCP
  packets and verifies that only marked host HTTPS gets the bootstrap allowance.
- Baseline HTTP arrives from the client interface, then connected HTTP arrives
  through VLESS/TLS from the server namespace.
- A separate REALITY/Vision profile carries real HTTP and system DNS, blocks a
  physical-interface bypass, and restores direct connectivity on disconnect.
  this runs for a legacy link and for Chrome, Firefox and Safari
  links with `support-x25519mlkem768=true`, using only generated local keys.
- `resolvectl query example.com` traverses the system resolver, TUN, VLESS and
  private HTTPS DNS responder.
- An HTTP socket explicitly bound to the physical fixture interface cannot
  bypass the active guard.
- Killing Xray with `SIGKILL` leaves traffic blocked before and after controller
  reconciliation.
- Killing the process that owns `Manager` stops its child Xray while the kernel
  firewall remains installed. Traffic stays blocked before a fresh Manager
  recovers persisted protection and establishes a new connection.
- Explicit disconnect restores direct HTTP and removes owned firewall/routing
  resources. The recovery scenario also checks restored HTTP and DNS.
- Real Xray debug output, process death, protection changes and failed VLESS
  authentication are recorded with immutable UID/profile/session ownership. A
  different user cannot read those records; UUID and REALITY credentials are
  removed before reports are written.
- The owner subprocess flushes its connection journal before being killed. The
  new owner reopens that private history and records a separate recovery session.

`TestRealVLESSOwnerProcess` is a subprocess helper and reports SKIP in the parent
test process. It runs in the child used by `TestRealVLESSOwnerDeathAndRecovery`.

## Results and cleanup

The container exits with the Go test exit code. `e2e.log`, `owner-process.log`,
server/DoH/resolver logs, private `connection-journal-*.json` reports, and final
route/firewall snapshots remain in the results directory. Test credentials are generated locally; private CA keys and core
configuration stay in the disposable container.

`--rm` removes the container, its namespaces, certificate trust and all runtime
network state after exit. No host resolver, VPN, routes or firewall are changed.
The local images and `.cache` results may be removed when no longer needed.

The current validation summary is in [docs/VALIDATION.md](../../docs/VALIDATION.md).
Containers share the host kernel; these scenarios do not replace physical boot
or ARM64 validation.

## Package installation and upgrade

Keep the baseline `dist/vault443_1.2.0_amd64.deb` and build the current package.
Build the PID1 fixture with `tests/Dockerfile.package-systemd`, using the
corresponding `vault443-platform-smoke` Ubuntu image as its base:

```sh
docker build --build-arg BASE_IMAGE=vault443-platform-smoke:24.04 \
  -t vault443-package-systemd:24.04 -f tests/Dockerfile.package-systemd tests
bash tests/package-systemd.sh 24.04
# Repeat with the 26.04 image and runner argument.
```

The runner starts real systemd, NetworkManager and resolved in a private cgroup
namespace with no external network. It checks the 1.2.0 upgrade under active
local VLESS and OpenVPN connections, continuously probes physical bypass during restart,
retains multiuser data and operator GID, rejects old/pending migrations, then
checks reinstall, removal and fresh APT installation. The host's system paths
are never mounted. Raw results stay under `test-results/<version>/`.

For a bootstrap-only run, pass
`--env VAULT443_E2E_TEST_PATTERN='^TestRealVLESSBootstrapFallbackAndCancellation$'`.
For the IPv6 capability/fallback regression, pass
`--env VAULT443_E2E_TEST_PATTERN='^TestRealVLESSIPv6UnavailableFallback$'`.
Parallel test builds can select different read-only fixture and test binaries
with `VAULT443_E2E_FIXTURE_BINARY` and `VAULT443_E2E_TEST_BINARY`; their defaults remain
`/src/.cache/e2e-fixture` and `/src/.cache/e2e.test`.
The existing cached `vault443-test:24.04` image also contains the required
24.04 E2E runtime dependencies. Always use `--pull never` for an offline cached
run. For packet-level bootstrap scope tests, compile `build-network.test` and run
`TestKernelBootstrapScopes` in `--network none --cap-add NET_ADMIN` with
`--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1`; these
forwarding values apply only to the disposable container namespace.

The resolver also uses HTTPS to disambiguate Go's `IsNotFound` result: Go merges
NXDOMAIN and NODATA into that flag. A valid HTTPS response distinguishes them;
if HTTPS confirmation itself fails, the original negative answer is retained as
“DNS returned no IPv4 address”, without claiming that the hostname is absent.
The same eight-second overall deadline and cancellation apply.

## NetworkManager connectivity regression

The image also includes NetworkManager. To opt in to its real, private-bus
fixture, add `--env VAULT443_E2E_NM=1` to the isolated `docker run` above. To run only
that case, also add:

```bash
--env VAULT443_E2E_TEST_PATTERN='^TestRealVLESSNetworkManagerConnectivity$'
```

It creates a managed physical fixture connection, verifies real NM `FULL`
connectivity through VLESS, and checks that an explicitly physical-bound probe
is still blocked. It exercises DNS, repeated reconciliation, NM restart, Xray
SIGKILL, reconnect, volatile-profile removal and preservation of the saved
physical profile's settings. Changing `VAULT443_E2E_NM_METRIC` from its default
`600` to `0` additionally tests a physical default at the minimum route metric.
Run on both distro images: NM 1.46 and newer NM versions differ in their
serialization of generated connections. This is a service/network test, not a
visual assertion about GNOME Shell's choice of icon.
