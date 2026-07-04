#!/usr/bin/env bash
# Build Linux install packages for the current machine architecture or TARGET.
#
# Run on Linux. The tray dependency may require native desktop development
# packages from your distro if you build the GUI-capable app.
set -euo pipefail

VERSION="${1:-0.1.0}"
TARGET="${TARGET:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/dist"
STAGE="${OUT}/stage"
PACKAGES="${OUT}/packages"
PKG="./cmd/deskaccess"
SIDECAR_MANIFEST="$ROOT/sidecars/iroh-sidecar/Cargo.toml"

go_env=()
package_slug=""
case "$TARGET" in
  linux-amd64) target="linux-amd64"; package_slug="linux-amd64"; deb_arch="amd64"; rust_target="x86_64-unknown-linux-gnu"; go_env=(env GOOS=linux GOARCH=amd64); deb_deps="libc6, libgtk-3-0, libayatana-appindicator3-1" ;;
  linux-arm64) target="linux-arm64"; package_slug="raspberry-pi-5-arm64"; deb_arch="arm64"; rust_target="aarch64-unknown-linux-gnu"; go_env=(env GOOS=linux GOARCH=arm64 CGO_ENABLED=0); deb_deps="libc6" ;;
  linux-armv7) target="linux-armv7"; package_slug="raspberry-pi-32bit-armv7"; deb_arch="armhf"; rust_target="armv7-unknown-linux-gnueabihf"; go_env=(env GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0); deb_deps="libc6" ;;
  "")
    arch="$(uname -m)"
    case "$arch" in
      x86_64)  target="linux-amd64"; package_slug="linux-amd64"; deb_arch="amd64"; rust_target="x86_64-unknown-linux-gnu"; go_env=(env GOOS=linux GOARCH=amd64); deb_deps="libc6, libgtk-3-0, libayatana-appindicator3-1" ;;
      aarch64) target="linux-arm64"; package_slug="raspberry-pi-5-arm64"; deb_arch="arm64"; rust_target="aarch64-unknown-linux-gnu"; go_env=(env GOOS=linux GOARCH=arm64 CGO_ENABLED=0); deb_deps="libc6" ;;
      armv7l|armv7*) target="linux-armv7"; package_slug="raspberry-pi-32bit-armv7"; deb_arch="armhf"; rust_target="armv7-unknown-linux-gnueabihf"; go_env=(env GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0); deb_deps="libc6" ;;
      *) echo "Unsupported Linux arch: $arch" >&2; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported TARGET: $TARGET" >&2; exit 1 ;;
esac

rm -rf "$STAGE"
mkdir -p "$PACKAGES"
rm -f "$PACKAGES"/deskaccess-"$VERSION"-linux-*.tar.gz \
  "$PACKAGES"/deskaccess-"$VERSION"-raspberry-pi-*.tar.gz \
  "$PACKAGES"/deskaccess_"$VERSION"_*.deb \
  "$PACKAGES"/deskaccess-"$VERSION"-raspberry-pi-*.deb \
  "$PACKAGES"/SHA256SUMS.txt

pkg_stage="$STAGE/deskaccess-$target"
mkdir -p "$pkg_stage"

echo "==> Building DeskAccess $VERSION for $target"
"${go_env[@]}" go build \
  -ldflags="-s -w -X main.version=${VERSION}" \
  -o "$pkg_stage/deskaccess-$target" \
  "$PKG"

echo "==> Building iroh sidecar for $rust_target"
cargo build \
  --manifest-path "$SIDECAR_MANIFEST" \
  --release \
  --target "$rust_target"
install -m 755 \
  "$ROOT/sidecars/iroh-sidecar/target/$rust_target/release/deskaccess-iroh-sidecar" \
  "$pkg_stage/deskaccess-iroh-sidecar"

cp "$ROOT/build/linux/install.sh" "$pkg_stage/"
cp "$ROOT/build/linux/uninstall.sh" "$pkg_stage/"
cp "$ROOT/build/linux/deskaccess.service" "$pkg_stage/"
cp "$ROOT/build/linux/deskaccess.desktop" "$pkg_stage/"
cp "$ROOT/resources/deskview-256.png" "$pkg_stage/deskaccess.png"

tar_pkg="$PACKAGES/deskaccess-$VERSION-$package_slug.tar.gz"
tar -C "$pkg_stage" -czf "$tar_pkg" .

deb_root="$STAGE/deskaccess-deb"
if [[ "$target" == linux-arm* ]]; then
  deb_pkg="$PACKAGES/deskaccess-${VERSION}-${package_slug}.deb"
else
  deb_pkg="$PACKAGES/deskaccess_${VERSION}_${deb_arch}.deb"
fi
rm -rf "$deb_root"
mkdir -p \
  "$deb_root/DEBIAN" \
  "$deb_root/usr/bin" \
  "$deb_root/usr/share/applications" \
  "$deb_root/usr/share/icons/hicolor/256x256/apps" \
  "$deb_root/lib/systemd/system" \
  "$deb_root/etc/deskaccess" \
  "$deb_root/var/lib/deskaccess"

install -m 755 "$pkg_stage/deskaccess-$target" "$deb_root/usr/bin/deskaccess"
install -m 755 "$pkg_stage/deskaccess-iroh-sidecar" "$deb_root/usr/bin/deskaccess-iroh-sidecar"
install -m 644 "$ROOT/resources/deskview-256.png" "$deb_root/usr/share/icons/hicolor/256x256/apps/deskaccess.png"
sed 's#^Exec=.*#Exec=sh -c '\''if [ -n "$1" ]; then exec /usr/bin/deskaccess "$1"; fi; url=$(/usr/bin/deskaccess 2>/dev/null | tail -n 1); exec xdg-open "$url"'\'' sh %u#' "$ROOT/build/linux/deskaccess.desktop" \
  > "$deb_root/usr/share/applications/deskaccess.desktop"
chmod 644 "$deb_root/usr/share/applications/deskaccess.desktop"
install -m 644 "$ROOT/build/linux/deskaccess.deb.service" "$deb_root/lib/systemd/system/deskaccess.service"
install -m 755 "$ROOT/build/linux/deb-postinst" "$deb_root/DEBIAN/postinst"
install -m 755 "$ROOT/build/linux/deb-prerm" "$deb_root/DEBIAN/prerm"
install -m 755 "$ROOT/build/linux/deb-postrm" "$deb_root/DEBIAN/postrm"

installed_size="$(du -sk "$deb_root/usr" "$deb_root/lib" "$deb_root/etc" 2>/dev/null | awk '{sum += $1} END {print sum}')"
cat > "$deb_root/DEBIAN/control" <<EOF
Package: deskaccess
Version: $VERSION
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: DeskAccess <support@DeskAccess.com>
Depends: $deb_deps
Installed-Size: $installed_size
Homepage: https://github.com/deskaccess/deskaccess
Description: App-scoped remote access for RDP, SSH, VNC, and custom TCP services
 DeskAccess provides secure remote access to selected local services without
 exposing the whole network through a VPN.
EOF

echo "==> Building Debian package"
dpkg-deb --build --root-owner-group "$deb_root" "$deb_pkg"

(
  cd "$PACKAGES"
  sha256sum deskaccess-"$VERSION"-*.tar.gz deskaccess*"$VERSION"*.deb > SHA256SUMS.txt
)

echo ""
echo "Packages written to:"
ls -lh "$tar_pkg"
ls -lh "$deb_pkg"
