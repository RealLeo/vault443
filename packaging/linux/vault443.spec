# The payload is built natively by build-linux-packages.sh and verified by the
# shared compiler/manifests/vulnerability gate before rpmbuild sees it.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
Name: vault443
Version: %{product_version}
Release: 1%{?dist}
Summary: Native desktop client for proxy and work VPN connections
License: LicenseRef-Unknown
ExclusiveArch: x86_64
Requires: qt6-qtbase-gui >= 6.4, qt6-qtdeclarative >= 6.4, qt6-qtwayland
Requires: systemd, systemd-resolved, dbus, ca-certificates
Requires: iproute, nftables, wireguard-tools, openvpn >= 2.6, shadow-utils
Requires(pre): /bin/sh
Requires(post): /bin/sh, shadow-utils, systemd
Requires(preun): /bin/sh, systemd, iproute, nftables

%description
A Qt Quick interface and privileged Go supervisor for VLESS, Trojan,
Shadowsocks/Outline, OpenVPN, WireGuard and AmneziaWG.
Project licensing is not yet declared; third-party notices are included.

%install
mkdir -p %{buildroot}
cp -a %{payload}/. %{buildroot}/

%pre
if test -e /var/lib/vless-terminal/state.json || test -L /var/lib/vless-terminal/state.json || test -e /var/lib/vault443-migration/active.json || test -L /var/lib/vault443-migration/active.json || rpm -q vless-terminal >/dev/null 2>&1; then
  echo 'Complete the VLESS Terminal transition with Vault 443 1.0.0 first.' >&2
  exit 1
fi

%post
/usr/lib/vault443/package-lifecycle configure

%posttrans
/usr/lib/vault443/package-lifecycle upgrade

%preun
if [ "$1" -eq 0 ]; then /usr/lib/vault443/package-lifecycle remove; fi

%postun
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  if [ "$1" -eq 0 ]; then systemctl stop vault443-guard.service || :; fi
fi

%files -f %{payload_files}
