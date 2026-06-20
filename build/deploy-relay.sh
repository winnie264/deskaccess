#!/usr/bin/env bash
# Deploy relay-server to a VPS in ~60 seconds.
# Tested on Ubuntu 22.04 / Debian 12.
#
# Usage:
#   ./deploy-relay.sh user@your-vps-ip
#
# What it does:
#   1. Builds relay-server binary for linux/amd64
#   2. Copies it to the VPS
#   3. Installs as a systemd service
#   4. Prints the multiaddr to paste into client configs
set -e

TARGET=${1:?"Usage: $0 user@host"}

echo "==> Building relay-server (linux/amd64)"
GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -o /tmp/relay-server \
  ./cmd/relay-server

echo "==> Uploading to $TARGET"
scp /tmp/relay-server "$TARGET:/tmp/relay-server"

echo "==> Installing on server"
ssh "$TARGET" bash <<'REMOTE'
set -e
install -m 755 /tmp/relay-server /usr/local/bin/relay-server
useradd -r -s /bin/false relay 2>/dev/null || true
mkdir -p /etc/relay
chown relay:relay /etc/relay

cat > /etc/systemd/system/DeskAccess-relay.service <<'SVC'
[Unit]
Description=DeskAccess Relay Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=relay
ExecStart=/usr/local/bin/relay-server \
  -addr /ip4/0.0.0.0/tcp/4001 \
  -key /etc/relay/key.hex \
  -reservation-ttl 24h \
  -max-reservations 1024
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVC

# Open firewall if ufw is active
if command -v ufw &>/dev/null && ufw status | grep -q active; then
  ufw allow 4001/tcp comment "DeskAccess relay"
fi

systemctl daemon-reload
systemctl enable --now DeskAccess-relay
sleep 2
systemctl status DeskAccess-relay --no-pager
REMOTE

echo ""
echo "==> Relay deployed. Multiaddr:"
ssh "$TARGET" journalctl -u DeskAccess-relay -n 20 --no-pager | grep "url  ="
