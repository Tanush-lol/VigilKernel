#!/bin/bash
# Add audit rules so user activity (logins, exec, key file changes) is logged.
# Run as root: sudo ./scripts/setup_audit_rules.sh

set -e
RULES_FILE="/etc/audit/rules.d/99-kernelshark.rules"

echo "Adding KernelShark audit rules to $RULES_FILE"

cat << 'AUDIT_EOF' | sudo tee "$RULES_FILE"
# KernelShark activity logger - user activity
-w /var/log/audit/audit.log -p rwa -k kernelshark_audit
-a always,exit -F arch=b64 -S execve -k kernelshark_exec
-a always,exit -F arch=b32 -S execve -k kernelshark_exec
-a always,exit -F arch=b64 -S openat -S open -F a1&0x2 -k kernelshark_write
-w /etc/passwd -p wa -k kernelshark_passwd
-w /etc/shadow -p wa -k kernelshark_shadow
-w /etc/group -p wa -k kernelshark_group
AUDIT_EOF

# Load rules
augenrules --load 2>/dev/null || true
echo "Done. Restart auditd if needed: sudo systemctl restart auditd"
echo "List rules: sudo ausearch -k kernelshark_exec"
