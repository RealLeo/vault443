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
  -e "DISTRO=$target" -e QT_QPA_PLATFORM=offscreen -e QT_QUICK_BACKEND=software \
  "vault443-linux-runtime:$target" bash -euc '
    case "$DISTRO" in
      debian13) dpkg -i /packages/*.deb; dpkg --audit;;
      fedora44) rpm -U /packages/*.rpm;;
      arch) pacman -U --noconfirm /packages/*.pkg.tar.zst;;
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
