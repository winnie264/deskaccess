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

# Create service group/user. Members of this group can ask the running service
# for a fresh dashboard URL through /run/deskaccess/DeskAccess.sock.
groupadd -r deskaccess 2>/dev/null || true
useradd -r -g deskaccess -s /bin/false -d /var/lib/deskaccess deskaccess 2>/dev/null || true
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  usermod -aG deskaccess "$SUDO_USER" || true
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
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  echo "If 'deskaccess' cannot reach the service yet, log out and back in so the deskaccess group membership is active."
fi
