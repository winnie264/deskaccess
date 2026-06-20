#!/usr/bin/env bash
# Build DeskAccess for all platforms
set -e

APP="DeskAccess"
PKG="./cmd/deskaccess"
OUT="dist"

mkdir -p "$OUT"

echo "==> Building Windows (amd64)"
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o "$OUT/${APP}-windows-amd64.exe" "$PKG"

echo "==> Building Linux (amd64)"
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$OUT/${APP}-linux-amd64" "$PKG"

echo "==> Building Linux (arm64 — Raspberry Pi 4/5)"
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$OUT/${APP}-linux-arm64" "$PKG"

echo "==> Building Linux (armv7 — Raspberry Pi 2/3)"
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "$OUT/${APP}-linux-armv7" "$PKG"

echo ""
echo "Binaries:"
ls -lh "$OUT/"
