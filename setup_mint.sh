#!/bin/bash
# ============================================================
# KernelShark UEBA - Full Setup Script for Linux Mint
# Run as: sudo bash setup_mint.sh
# ============================================================
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==========================================="
echo " KernelShark UEBA Setup - Linux Mint"
echo " Repo: $REPO_DIR"
echo "==========================================="

# --- Must be root ---
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run this script with sudo: sudo bash $0"
    exit 1
fi

# --- Step 1: System packages ---
echo ""
echo "[1/6] Installing system packages..."
apt-get update -qq
apt-get install -y \
    python3 python3-pip python3-venv \
    linux-headers-$(uname -r) \
    auditd \
    tshark \
    trace-cmd \
    python3-bpfcc bpfcc-tools \
    python3-pyudev

echo "[1/6] Done."

# --- Step 2: Python dependencies ---
echo ""
echo "[2/6] Installing Python dependencies..."
pip3 install --break-system-packages PyYAML pyudev pyshark 2>/dev/null \
    || pip3 install PyYAML pyudev pyshark
echo "[2/6] Done."

# --- Step 3: Audit rules ---
echo ""
echo "[3/6] Setting up audit rules..."
RULES_FILE="/etc/audit/rules.d/99-kernelshark.rules"
cat << 'AUDIT_EOF' > "$RULES_FILE"
# KernelShark UEBA audit rules
-w /var/log/audit/audit.log -p rwa -k kernelshark_audit
-a always,exit -F arch=b64 -S execve -k kernelshark_exec
-a always,exit -F arch=b32 -S execve -k kernelshark_exec
-a always,exit -F arch=b64 -S openat -S open -F a1&0x2 -k kernelshark_write
-w /etc/passwd -p wa -k kernelshark_passwd
-w /etc/shadow -p wa -k kernelshark_shadow
-w /etc/group -p wa -k kernelshark_group
AUDIT_EOF
augenrules --load 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true
echo "[3/6] Done."

# --- Step 4: Create log directories ---
echo ""
echo "[4/6] Creating log directories..."
mkdir -p /var/log/ueba
chmod 750 /var/log/ueba
echo "[4/6] Done."

# --- Step 5: Mount tracefs if needed ---
echo ""
echo "[5/6] Ensuring tracefs is mounted..."
if [ ! -d /sys/kernel/tracing/trace_pipe ]; then
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
fi
if [ -f /sys/kernel/tracing/trace_pipe ]; then
    echo "  tracefs OK at /sys/kernel/tracing"
else
    echo "  WARNING: tracefs not available (kernel trace features will be disabled)"
fi
echo "[5/6] Done."

# --- Step 6: Verify everything ---
echo ""
echo "[6/6] Verifying installation..."
PASS=true

check() {
    if eval "$1" 2>/dev/null; then
        echo "  OK: $2"
    else
        echo "  FAIL: $2"
        PASS=false
    fi
}

check "python3 -c 'import yaml'" "PyYAML"
check "python3 -c 'import pyudev'" "pyudev"
check "python3 -c 'import pyshark'" "pyshark"
check "python3 -c 'from bcc import BPF'" "BCC (eBPF)"
check "which tshark > /dev/null" "tshark"
check "which trace-cmd > /dev/null" "trace-cmd"
check "which auditctl > /dev/null" "auditd"
check "test -f /sys/kernel/tracing/trace_pipe" "tracefs"

# Verify UEBA config loads
cd "$REPO_DIR/ueba"
check "python3 -c 'import sys; sys.path.insert(0,\".\"); from config_parser import load_config; load_config(); print(\"config OK\")'" "UEBA config"

echo ""
echo "==========================================="
if $PASS; then
    echo " ALL CHECKS PASSED"
else
    echo " Some checks failed (see above). Non-BCC items"
    echo " can still work with --no-ebpf flag."
fi
echo "==========================================="
echo ""
echo " To run the UEBA daemon (eBPF + user-space):"
echo "   cd $REPO_DIR/ueba"
echo "   sudo python3 main.py -c config/config.yaml"
echo ""
echo " To run without eBPF:"
echo "   sudo python3 main.py -c config/config.yaml --no-ebpf"
echo ""
echo " To run the plain-text logger:"
echo "   cd $REPO_DIR"
echo "   sudo python3 main.py"
echo ""
echo " View logs:"
echo "   sudo tail -f /var/log/ueba/events.log"
echo "   sudo tail -f /var/log/kernelshark_activity.log"
echo "==========================================="
