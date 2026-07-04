#!/usr/bin/env bash
# Install DeskAccess on Linux / Raspberry Pi
set -e

ARCH=$(uname -m)
case $ARCH in
  x86_64)  BIN="deskaccess-linux-amd64" ;;
  aarch64) BIN="deskaccess-linux-arm64" ;;
  armv7l)  BIN="deskaccess-linux-armv7" ;;
  *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

echo "Installing $BIN..."

# Copy binary
install -m 755 "$BIN" /usr/local/bin/deskaccess
if [ -f deskaccess-iroh-sidecar ]; then
  install -m 755 deskaccess-iroh-sidecar /usr/local/bin/deskaccess-iroh-sidecar
fi

# Create service group/user. Members of this group can ask the running service
# for a fresh dashboard URL through /run/deskaccess/DeskAccess.sock.
groupadd -r deskaccess 2>/dev/null || true
useradd -r -g deskaccess -s /bin/false -d /var/lib/deskaccess deskaccess 2>/dev/null || true
add_user_to_group() {
  user="$1"
  if [ -n "$user" ] && [ "$user" != "root" ] && id "$user" >/dev/null 2>&1; then
    usermod -aG deskaccess "$user" || true
    return 0
  fi
  return 1
}

added_user=false
if add_user_to_group "${SUDO_USER:-}"; then
  added_user=true
fi

if [ "$added_user" = false ] && [ -n "${PKEXEC_UID:-}" ]; then
  pk_user="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
  if add_user_to_group "$pk_user"; then
    added_user=true
  fi
fi

if [ "$added_user" = false ] && command -v logname >/dev/null 2>&1; then
  if add_user_to_group "$(logname 2>/dev/null)"; then
    added_user=true
  fi
fi

if [ "$added_user" = false ]; then
  awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd |
    while IFS= read -r user; do
      add_user_to_group "$user" || true
    done
fi

# Create config dir
mkdir -p /etc/deskaccess /var/lib/deskaccess
chown deskaccess:deskaccess /etc/deskaccess /var/lib/deskaccess

# Install systemd service
install -m 644 deskaccess.service /etc/systemd/system/

# Install desktop launcher metadata when icon assets are present.
if [ -f deskaccess.png ]; then
  install -Dm 644 deskaccess.png /usr/share/icons/hicolor/256x256/apps/deskaccess.png
fi
if [ -f deskaccess.desktop ]; then
  install -Dm 644 deskaccess.desktop /usr/share/applications/deskaccess.desktop
  sed -i 's#^Exec=.*#Exec=sh -c '\''if [ -n "$1" ]; then exec /usr/local/bin/deskaccess "$1"; fi; url=$(/usr/local/bin/deskaccess 2>/dev/null | tail -n 1); exec xdg-open "$url"'\'' sh %u#' /usr/share/applications/deskaccess.desktop
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default deskaccess.desktop x-scheme-handler/deskaccess || true
fi

systemctl daemon-reload
systemctl enable deskaccess
systemctl start deskaccess

echo "Done. DeskAccess running."
echo "Run 'deskaccess' to print a fresh dashboard URL."
echo "If 'deskaccess' cannot reach the service yet, log out and back in so the deskaccess group membership is active."
