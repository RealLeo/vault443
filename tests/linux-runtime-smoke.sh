#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:?Expected debian13, fedora44 or arch}
case "$target" in debian13|fedora44|arch) ;; *) exit 2;; esac
version=$(cat VERSION)
results="$PWD/test-results/linux-$version/$target-runtime"
mkdir -p "$results"
# The runtime stage deliberately omits compilers, Qt headers and test tools:
# these must not conceal an undeclared GUI/package dependency.
docker build --target runtime -f "packaging/linux/Dockerfile.$target" \
  -t "vault443-linux-runtime:$target" packaging/linux
docker run --rm --network none --pull never \
  --mount "type=bind,src=$PWD/dist/linux/$target,dst=/packages,readonly" \
  --mount "type=bind,src=$results,dst=/results" \
  -e "DISTRO=$target" -e "PRODUCT_VERSION=$version" -e QT_QPA_PLATFORM=offscreen -e QT_QUICK_BACKEND=software \
  "vault443-linux-runtime:$target" bash -euc '
    case "$DISTRO" in
      debian13) dpkg -i "/packages/vault443_${PRODUCT_VERSION}-1debian13_amd64.deb"; dpkg --audit;;
      fedora44) rpm -U "/packages/vault443-${PRODUCT_VERSION}-1.fc44.x86_64.rpm";;
      arch)
        # The official minimal Arch image skips documentation by default. This
        # test verifies the whole artifact, including bundled licenses/docs.
        sed -i '/^NoExtract[[:space:]]*=/d' /etc/pacman.conf
        pacman -U --noconfirm "/packages/vault443-${PRODUCT_VERSION}-1-x86_64.pkg.tar.zst";;
    esac
    vault443d --version
    vault443d --check
    for language in en ru; do
      LANGUAGE=$language timeout 20s vault443 --demo --screenshot /results/$language.png
      test -s /results/$language.png
    done
    case "$DISTRO" in
      debian13) dpkg-query -W vault443;;
      fedora44) rpm -q vault443; rpm -V vault443;;
      arch) pacman -Q vault443; pacman -Qkk vault443;;
    esac
  '
echo "PASS: $target clean runtime dependency closure and installed EN/RU GUI"
