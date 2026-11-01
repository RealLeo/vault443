#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
arch="${1:-$(dpkg --print-architecture)}"
case "$arch" in amd64|arm64) ;; *) echo 'Supported architectures: amd64, arm64' >&2; exit 1;; esac
build_dir="${BUILD_DIR:-build}"
version="$(cat VERSION)"
python3 scripts/check-vulnerabilities.py --verify
stage="dist/stage-$arch"
test -x "$build_dir/vault443"
test -x "$build_dir/vault443d"
test -x ".cache/xray/$arch/xray"
test -x ".cache/amneziawg/$arch/amneziawg-go"
for binary in "$build_dir/vault443" "$build_dir/vault443d" ".cache/xray/$arch/xray" ".cache/amneziawg/$arch/amneziawg-go" ".cache/outline/$arch/vault443-outline"; do
  case "$arch:$(file -b "$binary")" in
    amd64:*x86-64*|arm64:*aarch64*) ;;
    *) echo "Architecture mismatch in $binary; cross-build first." >&2; exit 1;;
  esac
done
python3 - "$arch" "$build_dir" <<'PY'
import hashlib, json, pathlib, sys
arch = sys.argv[1]
build_dir = pathlib.Path(sys.argv[2])
sys.path.insert(0, 'scripts')
import toolchain
compiler, compiler_env = toolchain.ensure()
for binary in [build_dir/'vault443d', pathlib.Path('.cache/amneziawg')/arch/'amneziawg-go', pathlib.Path('.cache/outline')/arch/'vault443-outline']:
    toolchain.verify_binary(compiler, compiler_env, binary)
service_manifest = json.loads((build_dir/'vault443d.build.json').read_text())
if service_manifest != dict(goVersion=toolchain.LOCK['version'], architecture=arch,
    productVersion=pathlib.Path('VERSION').read_text().strip(),
    binarySha256=hashlib.sha256((build_dir/'vault443d').read_bytes()).hexdigest(),
    goSumSha256=hashlib.sha256(pathlib.Path('go.sum').read_bytes()).hexdigest()):
    raise SystemExit('Supervisor build manifest mismatch; rebuild first.')
lock = json.loads(pathlib.Path('packaging/amneziawg-lock.json').read_text())
root = pathlib.Path('.cache/amneziawg') / arch
manifest = json.loads((root / 'build.json').read_text())
if any(manifest.get(key) != value for key, value in lock.items()):
    raise SystemExit('AmneziaWG build does not match the pinned source/toolchain; rebuild first.')
if manifest.get('goVersion') != toolchain.LOCK['version'] or manifest.get('architecture') != arch or manifest.get('binarySha256') != hashlib.sha256((root / 'amneziawg-go').read_bytes()).hexdigest():
    raise SystemExit('AmneziaWG binary does not match its build manifest; rebuild first.')
if not (root / 'licenses').is_dir():
    raise SystemExit('AmneziaWG dependency licenses are missing; rebuild first.')
root = pathlib.Path('.cache/outline') / arch
lock = json.loads(pathlib.Path('packaging/outline-lock.json').read_text())
manifest = json.loads((root / 'build.json').read_text())
if any(manifest.get(k) != v for k, v in lock.items()) or manifest.get('architecture') != arch:
    raise SystemExit('Outline pin/architecture mismatch; rebuild first.')
if manifest.get('goVersion') != toolchain.LOCK['version'] or manifest.get('productVersion') != pathlib.Path('VERSION').read_text().strip() or manifest.get('binarySha256') != hashlib.sha256((root / 'vault443-outline').read_bytes()).hexdigest() or manifest.get('goSumSha256') != hashlib.sha256(pathlib.Path('helpers/outline/go.sum').read_bytes()).hexdigest():
    raise SystemExit('Outline build manifest mismatch; rebuild first.')
if not (root / 'licenses/modules.json').is_file():
    raise SystemExit('Outline licenses are missing; rebuild first.')
PY
if readelf -d "$build_dir/vault443" | awk '/\((RPATH|RUNPATH)\)/ { found=1 } END { exit !found }'; then
  echo 'Build with -DCMAKE_SKIP_RPATH=ON before packaging; local library paths are forbidden.' >&2
  exit 1
fi
rm -rf "$stage"
install -d "$stage"/{DEBIAN,usr/bin,usr/sbin,usr/lib/vault443,usr/lib/systemd/system,usr/share/{applications,icons/hicolor/256x256/apps,dbus-1/system.d,dbus-1/system-services,doc/vault443}}
install -m755 "$build_dir/vault443" "$stage/usr/bin/"
install -m755 "$build_dir/vault443d" "$stage/usr/sbin/"
install -m755 ".cache/xray/$arch/xray" "$stage/usr/lib/vault443/"
install -m755 ".cache/amneziawg/$arch/amneziawg-go" "$stage/usr/lib/vault443/"
install -m755 ".cache/outline/$arch/vault443-outline" "$stage/usr/lib/vault443/"
install -m755 packaging/vault443-access "$stage/usr/sbin/"
install -m644 packaging/vault443.service "$stage/usr/lib/systemd/system/"
install -m644 packaging/vault443-guard.service "$stage/usr/lib/systemd/system/"
for unit in NetworkManager.service systemd-networkd.service; do
  install -d "$stage/usr/lib/systemd/system/$unit.d"
  install -m644 packaging/require-guard.conf "$stage/usr/lib/systemd/system/$unit.d/vault443.conf"
done
install -m644 packaging/org.vault443.Service1.conf "$stage/usr/share/dbus-1/system.d/"
install -m644 packaging/org.vault443.Service1.service "$stage/usr/share/dbus-1/system-services/"
install -m644 packaging/vault443.desktop "$stage/usr/share/applications/"
install -m644 assets/profile-icons/vault-door.png "$stage/usr/share/icons/hicolor/256x256/apps/vault443.png"
for f in preinst postinst prerm postrm; do install -m755 "packaging/$f" "$stage/DEBIAN/$f"; done
install -m644 README.md "$stage/usr/share/doc/vault443/"
install -m644 VERSION "$stage/usr/share/doc/vault443/"
install -m644 packaging/go-toolchain-lock.json "$stage/usr/share/doc/vault443/"
install -m644 "$build_dir/vault443d.build.json" "$build_dir/Go-LICENSE" "$stage/usr/share/doc/vault443/"
install -m644 packaging/xray-lock.json "$stage/usr/share/doc/vault443/"
install -m644 packaging/amneziawg-lock.json "$stage/usr/share/doc/vault443/"
install -d "$stage/usr/share/doc/vault443/amneziawg"
cp -a ".cache/amneziawg/$arch/licenses" "$stage/usr/share/doc/vault443/amneziawg/"
install -m644 ".cache/amneziawg/$arch/build.json" "$stage/usr/share/doc/vault443/amneziawg/"
install -m644 packaging/outline-lock.json "$stage/usr/share/doc/vault443/"
install -d "$stage/usr/share/doc/vault443/outline"
cp -a ".cache/outline/$arch/licenses" "$stage/usr/share/doc/vault443/outline/"
install -m644 ".cache/outline/$arch/build.json" "$stage/usr/share/doc/vault443/outline/"
cp -a packaging/licenses "$stage/usr/share/doc/vault443/service-licenses"
cp -a docs "$stage/usr/share/doc/vault443/"
install -m644 assets/fonts/*LICENSE* "$stage/usr/share/doc/vault443/"
test ! -f ".cache/xray/$arch/LICENSE" || install -m644 ".cache/xray/$arch/LICENSE" "$stage/usr/share/doc/vault443/Xray-LICENSE"
cat > "$stage/DEBIAN/control" <<EOF
Package: vault443
Version: $version
Architecture: $arch
Maintainer: Vault 443 project
Section: net
Priority: optional
Depends: libc6 (>= 2.39), libstdc++6, libqt6core6t64 (>= 6.4) | libqt6core6 (>= 6.4), libqt6gui6t64 | libqt6gui6, libqt6widgets6t64 | libqt6widgets6, libqt6dbus6t64 | libqt6dbus6, libqt6quick6, libqt6quickcontrols2-6, qml6-module-qtquick, qml6-module-qtquick-controls, qml6-module-qtquick-layouts, qml6-module-qtquick-window, qml6-module-qtquick-templates, qml6-module-qtquick-dialogs, qml6-module-qtqml, qml6-module-qtqml-workerscript, qt6-qpa-plugins, qt6-wayland, systemd, systemd-resolved, ca-certificates, dbus, iproute2, nftables, wireguard-tools, openvpn (>= 2.6), adduser, passwd, init-system-helpers
Description: Native desktop client for proxy and work VPN connections
 A native Qt Quick GUI and a privileged Go supervisor for VLESS, Trojan, Shadowsocks/Outline, OpenVPN, WireGuard and AmneziaWG.
EOF
temporary=$(mktemp "dist/.vault443-${version}-${arch}-XXXXXX.deb")
trap 'rm -f "$temporary"' EXIT
dpkg-deb --root-owner-group --build "$stage" "$temporary"
mv "$temporary" "dist/vault443_${version}_${arch}.deb"
(cd dist && sha256sum "vault443_${version}_${arch}.deb" > "vault443_${version}_${arch}.deb.sha256")
