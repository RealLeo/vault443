#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
arch="${1:-$(dpkg --print-architecture)}"
version="$(cat VERSION)"
stage="${PACKAGE_STAGE:-dist/stage-$arch}"
bash scripts/stage-package.sh "$arch"
install -d "$stage/DEBIAN"
for f in preinst postinst prerm postrm; do install -m755 "packaging/$f" "$stage/DEBIAN/$f"; done
cat > "$stage/DEBIAN/control" <<EOF
Package: vault443
Version: ${PACKAGE_VERSION:-$version}
Architecture: $arch
Maintainer: Vault 443 project
Section: net
Priority: optional
Depends: libc6 (>= ${LIBC_MIN:-2.39}), libstdc++6, libqt6core6t64 (>= ${QT_MIN:-6.4}) | libqt6core6 (>= ${QT_MIN:-6.4}), libqt6gui6t64 | libqt6gui6, libqt6widgets6t64 | libqt6widgets6, libqt6dbus6t64 | libqt6dbus6, libqt6quick6, libqt6quickcontrols2-6, qml6-module-qtquick, qml6-module-qtquick-controls, qml6-module-qtquick-layouts, qml6-module-qtquick-window, qml6-module-qtquick-templates, qml6-module-qtquick-dialogs, qml6-module-qtqml, qml6-module-qtqml-workerscript, qt6-qpa-plugins, qt6-wayland, systemd, systemd-resolved, ca-certificates, dbus, iproute2, nftables, wireguard-tools, openvpn (>= 2.6), adduser, passwd, init-system-helpers
Description: Native desktop client for proxy and work VPN connections
 A native Qt Quick GUI and a privileged Go supervisor for VLESS, Trojan, Shadowsocks/Outline, OpenVPN, WireGuard and AmneziaWG.
EOF
output="${PACKAGE_OUTPUT:-dist/vault443_${version}_${arch}.deb}"
temporary=$(mktemp "dist/.vault443-${version}-${arch}-XXXXXX.deb")
trap 'rm -f "$temporary"' EXIT
dpkg-deb --root-owner-group --build "$stage" "$temporary"
chmod 644 "$temporary"
mv "$temporary" "$output"
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
