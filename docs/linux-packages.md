# Linux packages — Vault 443 1.3.1

Native x86-64 packages are built separately for each distribution. This is a
packaging revision of 1.3.1, not an engine or profile-format upgrade. The directory
name `vless-terminal` does not affect the installed product identity.

| Target | Artifact under `dist/linux/` | Scope |
| --- | --- | --- |
| Ubuntu 24.04 / 26.04 | `ubuntu24/vault443_1.3.1-1ubuntu24.04_amd64.deb` | Existing Ubuntu runtime baseline |
| Debian 13 (trixie) | `debian13/vault443_1.3.1-1debian13_amd64.deb` | Native Debian 13 Qt/glibc build; not Debian 12 |
| Fedora 44 | `fedora44/vault443-1.3.1-1.fc44.x86_64.rpm` | Native Fedora build; desktop/SELinux acceptance pending |
| Arch Linux | `arch/vault443-1.3.1-1-x86_64.pkg.tar.zst` | Native rolling-release build; perform full system updates |

Each artifact has a `.sha256` file. Native container builds also record their
image identity, exact package inventory and output checksum in `.build.json`.
Packages are local, unsigned artifacts; no distribution repository, COPR or AUR
submission is implied. RPM and Arch use `LicenseRef-Unknown` because this project
does not yet declare its own license. Bundled third-party license notices remain
included. The existing ARM64 Ubuntu build is separate from this x86-64 matrix.

## Install

Use the command for your distribution, from the repository root:

```sh
# Ubuntu 24.04 or 26.04
sudo apt install ./dist/linux/ubuntu24/vault443_1.3.1-1ubuntu24.04_amd64.deb

# Debian 13
sudo apt install ./dist/linux/debian13/vault443_1.3.1-1debian13_amd64.deb

# Fedora 44
sudo dnf install ./dist/linux/fedora44/vault443-1.3.1-1.fc44.x86_64.rpm

# Arch Linux: full upgrade first, not a partial Qt upgrade
sudo pacman -Syu
sudo pacman -U ./dist/linux/arch/vault443-1.3.1-1-x86_64.pkg.tar.zst
```

Check the checksum in the directory containing the downloaded package:

```sh
sha256sum -c vault443-1.3.1-1.fc44.x86_64.rpm.sha256
```

On **Fedora and Arch**, system services are intentionally not started or enabled
on a fresh install. First ensure that the machine already uses systemd-resolved
for DNS (see below), then enable Vault 443:

```sh
sudo systemctl enable --now vault443-guard.service vault443.service
```

For every distribution, grant access once from the ordinary desktop user's
terminal, then open **Vault 443** in the launcher:

```sh
sudo vault443-access "$USER"
```

Do not launch the GUI with sudo. Daily connections require an active local
desktop session and membership of `vault443`. Additional administrative actions
accept `sudo`, `admin` or `wheel` membership, and still require enrollment in
`vault443` and a local session. Existing profiles, IDs and user settings keep
their current locations and formats.

## DNS and desktop prerequisites

The supported network stack is **systemd + D-Bus/logind + systemd-resolved**,
with NetworkManager or systemd-networkd. The package does not rewrite
`/etc/resolv.conf`, change NetworkManager settings, replace another DNS service,
or disable SELinux/firewalld. Merely installing `resolvectl` is insufficient.

Check `systemctl is-active systemd-resolved` and `resolvectl status` before the
first connection. On Arch installations using a different DNS resolver, configure
systemd-resolved and its network-manager integration first, following the
[Arch systemd-resolved guide](https://wiki.archlinux.org/title/Systemd-resolved)
and [NetworkManager DNS documentation](https://wiki.archlinux.org/title/NetworkManager#systemd-resolved).
For NetworkManager, `dns=systemd-resolved` belongs in a `[main]` section of a
configuration file in `/etc/NetworkManager/conf.d/`; the system resolver must
also use resolved. Preserve the previous configuration before changing it.
Vault 443 deliberately does not make that system-wide transition on installation.

Kernel WireGuard and `/dev/net/tun` must be available. AmneziaWG is bundled as a
userspace process and needs no DKMS installation. The GNOME tray still depends
on the desktop's StatusNotifier/AppIndicator support; the application can be
reopened from its launcher when no tray host is present.

Fedora's enforcing SELinux policy and firewalld interactions need acceptance on
a Fedora VM or device. Containers on an Ubuntu host cannot validate that policy.
Do not disable either protection to work around a failure. Inspect the service
journal and SELinux AVC records and report the denied operation instead. Fedora
and Arch packages are initial distribution ports, not certification of every
desktop or derivative (Silverblue, RHEL, Artix and Manjaro are not tested targets).

## Updates and removal

Repeat the same package-manager install command for updates. RPM/pacman only
restart Vault 443 when it was already running. Restarting preserves connection
intent and the traffic guard; it does not call `--release-network`. Group IDs,
membership and private data remain intact. First-install activation remains an
explicit administrator step on Fedora/Arch.

```sh
sudo apt remove vault443       # Ubuntu / Debian
sudo dnf remove vault443       # Fedora
sudo pacman -R vault443        # Arch
```

Removal explicitly stops Vault 443, releases its network resources, and leaves
other firewall rules intact. The guard is stopped only after its NetworkManager
dependencies have been unloaded. Private files in `/var/lib/vault443`, access
group membership and desktop settings are retained. Do not use `--nodeps`,
`--noscripts` or manual deletion of package files as an uninstall method.

## Build and validate

Use the existing [source-build prerequisites](../README.md#build-from-source)
to prepare the pinned Go 1.27.3, Xray, AmneziaWG and Outline caches. Docker is
required; do not run the driver as root. System Go is never selected implicitly.

```sh
python3 scripts/check-vulnerabilities.py
python3 scripts/build-linux-packages.py debian13 fedora44 arch

# Existing native Ubuntu build, with a distro packaging revision:
bash scripts/build.sh
mkdir -p dist/linux/ubuntu24
PACKAGE_VERSION=1.3.1-1ubuntu24.04 \
  PACKAGE_OUTPUT=dist/linux/ubuntu24/vault443_1.3.1-1ubuntu24.04_amd64.deb \
  bash scripts/package.sh amd64
```

Dockerfiles pin official base-image digests; distribution repository updates are
resolved at build time, and the resulting inventory is recorded. This is not a
claim of byte-identical rebuilds from moving package repositories. Keep the build
image by its recorded ID to reproduce its exact native Qt environment. GUI builds
run without network, as the host's unprivileged UID. The shared staging gate
checks all Go build manifests, compiler versions, architecture, runtime RPATH
and a fresh vulnerability report before any package format is produced.

```sh
# Runtime dependency closure, without developer packages:
bash tests/linux-runtime-smoke.sh debian13
bash tests/linux-runtime-smoke.sh fedora44
bash tests/linux-runtime-smoke.sh arch

# Separate PID1, cgroups and network namespace; synthetic VPN servers only:
bash tests/test-linux-package.sh debian13
bash tests/test-linux-package.sh fedora44
bash tests/test-linux-package.sh arch
bash tests/test-linux-package.sh ubuntu24
bash tests/test-linux-package.sh ubuntu26

# Native Qt asynchronous/private-bus regression checks:
bash tests/linux-gui-dbus.sh debian13
bash tests/linux-gui-dbus.sh fedora44
bash tests/linux-gui-dbus.sh arch
```

These privileged test containers have no external network and never mount the
host's `/etc`, `/run`, `/var/lib` or cgroup hierarchy. Logs and screenshots go to
ignored `test-results/linux-1.3.1/`. See [validation](VALIDATION.md) for executed
checks and the distinction between container tests and physical-machine support.
