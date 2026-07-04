#!/usr/bin/env bash
# Uninstall DeskAccess installed by build/linux/install.sh.
set -e

KEEP_DATA="${KEEP_DATA:-0}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop deskaccess.service 2>/dev/null || true
  systemctl disable deskaccess.service 2>/dev/null || true
fi

rm -f /etc/systemd/system/deskaccess.service
rm -f /usr/local/bin/deskaccess
rm -f /usr/local/bin/deskaccess-iroh-sidecar
rm -f /usr/share/applications/deskaccess.desktop
rm -f /usr/share/icons/hicolor/256x256/apps/deskaccess.png
rm -f /etc/sysctl.d/99-deskaccess-quic.conf
rm -f /run/deskaccess/DeskAccess.sock 2>/dev/null || true
rmdir /run/deskaccess 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications || true
fi

if [ "$KEEP_DATA" != "1" ]; then
  rm -rf /etc/deskaccess /var/lib/deskaccess
  userdel deskaccess 2>/dev/null || true
  groupdel deskaccess 2>/dev/null || true
fi

echo "DeskAccess uninstalled."
if [ "$KEEP_DATA" = "1" ]; then
  echo "Kept /etc/deskaccess, /var/lib/deskaccess, and the deskaccess user/group."
fi
