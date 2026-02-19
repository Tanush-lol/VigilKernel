# UEBA - User and Entity Behavior Analytics
# No compilation needed when using BCC (compiles eBPF on the fly).
# This Makefile provides run, install-deps, and check targets.

PREFIX ?= /usr/local
UEBA_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: run run-no-ebpf install-deps check

# Run the daemon (requires root)
run:
	sudo python3 $(UEBA_DIR)/main.py -c $(UEBA_DIR)/config/config.yaml

# Run without eBPF (user-space sources only; still needs root for audit/wtmp)
run-no-ebpf:
	sudo python3 $(UEBA_DIR)/main.py -c $(UEBA_DIR)/config/config.yaml --no-ebpf

# Install Python and system dependencies (Linux Mint / Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y python3 python3-pip linux-headers-$$(uname -r)
	# BCC for eBPF (optional but recommended)
	sudo apt-get install -y python3-bpfcc bpfcc-tools || true
	pip3 install --user PyYAML || sudo pip3 install PyYAML
	# For block/device events
	pip3 install --user pyudev || sudo pip3 install pyudev

# Check config and Python deps
check:
	python3 -c "from config_parser import load_config; from pathlib import Path; c=load_config(Path('$(UEBA_DIR)/config/config.yaml')); print('Config OK')"
	@echo "Run as root: sudo python3 $(UEBA_DIR)/main.py"
