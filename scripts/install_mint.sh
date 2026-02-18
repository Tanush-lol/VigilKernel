#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/vigilkernel"
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_DIR="/etc/ueba"
LOG_DIR="/var/log/ueba"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install_mint.sh"
  exit 1
fi

echo "[1/7] Installing apt packages"
apt update
apt install -y \
  python3 \
  python3-venv \
  python3-pip \
  python3-bpfcc \
  bpfcc-tools \
  libbpfcc-dev \
  linux-headers-"$(uname -r)" \
  clang \
  llvm \
  make

echo "[2/7] Installing project files into $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
  --exclude '.git' \
  --exclude '__pycache__' \
  "$REPO_DIR"/ "$INSTALL_DIR"/

echo "[3/7] Creating Python virtual environment"
python3 -m venv --system-site-packages "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "[4/7] Creating config + log directories"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
cp "$INSTALL_DIR/config/config.yaml" "$CONFIG_DIR/config.yaml"
chown -R root:root "$CONFIG_DIR" "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Ensure log file exists before first tail/read
: > "$LOG_DIR/events.log"
chown root:root "$LOG_DIR/events.log"
chmod 640 "$LOG_DIR/events.log"

echo "[5/7] Installing systemd service"
cp "$INSTALL_DIR/deploy/ueba.service" /etc/systemd/system/ueba.service
systemctl daemon-reload

echo "[6/7] Enabling and starting service"
systemctl enable --now ueba.service

echo "[7/7] Done"
echo "Service status:"
systemctl --no-pager --full status ueba.service || true
echo
echo "Recent logs:"
tail -n 20 "$LOG_DIR/events.log" || true
