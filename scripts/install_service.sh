#!/bin/bash
# Install KernelShark activity logger and optional systemd service.
# Run from repo root: ./scripts/install_service.sh

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/kernelshark}"

echo "Installing from $REPO_ROOT to $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo cp "$REPO_ROOT"/*.py "$REPO_ROOT"/config.yaml "$REPO_ROOT"/requirements.txt "$INSTALL_DIR/"
sudo python3 -m pip install -r "$INSTALL_DIR/requirements.txt" --break-system-packages 2>/dev/null || sudo python3 -m pip install -r "$INSTALL_DIR/requirements.txt" --user || true

# systemd
sudo cp "$REPO_ROOT/kernelshark-logger.service" /etc/systemd/system/
sudo sed -i "s|/opt/kernelshark|$INSTALL_DIR|g" /etc/systemd/system/kernelshark-logger.service
sudo systemctl daemon-reload
echo "Installed. Enable and start: sudo systemctl enable --now kernelshark-logger"
echo "Log file: edit config.yaml log_file or use default /var/log/kernelshark_activity.log"
echo "Ensure /var/log is writable or set log_file in config to a path you can write."
