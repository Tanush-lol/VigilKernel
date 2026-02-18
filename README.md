# VigilKernel UEBA (Kernel-Level Linux Telemetry)

This repository provides a functional **starting UEBA skeleton** for Debian-based Linux systems (including Linux Mint) using:

- **eBPF + BCC** for kernel instrumentation
- **Python 3** for monitor orchestration and JSON-lines logging

It captures process execution, file open events, network socket activity, user/session updates, and key privilege-related events.

## Important: Installing in Linux Mint VM (VirtualBox)

You **do not need to merge this project into the Mint ISO**.
The recommended flow is:

1. Install Linux Mint normally in VirtualBox.
2. Boot into Mint.
3. Clone/copy this repo inside the VM.
4. Run the included install script:
   ```bash
   sudo bash scripts/install_mint.sh
   ```
5. Validate service and logs.

### Should you "bind/combine" with ISO?

Usually **no**. Rebuilding an ISO is only needed for enterprise unattended provisioning. For development/testing, post-install deployment (script + systemd service) is simpler and much more reliable.

### Optional: Auto-install after first boot

If you still want near-automatic deployment:
- Keep Mint ISO unchanged.
- Use a VirtualBox shared folder or cloud-init style first-boot script to run `scripts/install_mint.sh` after OS installation completes.

---

## Features

- Process execution tracing (`execve`, scheduler process exec events)
- File open tracing (`open`, `openat` syscall tracepoints)
- Network telemetry (connect, accept, bind, listen)
- Privilege/security-related telemetry (`setuid`, `capset`, kernel module loads)
- User activity polling via `last` (wtmp/session updates)
- Structured JSON-lines logging with rotation
- Config-driven monitor toggles and simple process-name filters

## Repository Layout

- `main.py` - daemon entry point
- `config/config.yaml` - default runtime configuration
- `deploy/ueba.service` - systemd unit for persistent startup
- `scripts/install_mint.sh` - one-command installer for Mint/Debian VMs
- `ueba/config_parser.py` - YAML configuration parser
- `ueba/logger.py` - rotating JSON-lines logger
- `ueba/bpf_loader.py` - BCC compile/load logic + perf callbacks
- `ueba/user_activity.py` - user/session activity polling monitor
- `ueba/utils.py` - helpers (IP conversion, process name lookup, bytes decoding)
- `bpf/exec_monitor.c` - exec tracepoints
- `bpf/file_monitor.c` - file open tracepoints
- `bpf/net_monitor.c` - socket activity kprobes/kretprobes
- `bpf/priv_monitor.c` - privilege/security tracepoints

## Requirements

- Linux kernel **5.4+** (recommended)
- Root privileges
- Python 3.10+
- BCC and Python bindings (from distro packages)

## Quick Install on Mint VM

```bash
git clone <your-repo-url> VigilKernel
cd VigilKernel
sudo bash scripts/install_mint.sh
```

Installer actions:
1. Installs apt dependencies (`python3-bpfcc`, headers, clang/llvm, etc.).
2. Copies project to `/opt/vigilkernel`.
3. Creates Python venv with `--system-site-packages` so distro `python3-bpfcc` is visible, then installs pip deps.
4. Copies config to `/etc/ueba/config.yaml`.
5. Installs and starts `ueba.service`.

## Manual Install (alternative)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-bpfcc bpfcc-tools libbpfcc-dev linux-headers-$(uname -r) clang llvm make
pip3 install -r requirements.txt   # installs pyyaml (BCC comes from apt python3-bpfcc)
```

> Depending on distro packaging, `bcc` Python package may already be provided by `python3-bpfcc`.

## Configuration

Default config: `config/config.yaml`

```yaml
monitors:
  process_exec: true
  file_open: true
  network: true
  user_activity: true
  privilege_events: true

logging:
  path: /var/log/ueba/events.log
  max_size_mb: 50
  backups: 5

filters:
  exclude_comm: ["chrome", "firefox"]
```

If running as a service, edit `/etc/ueba/config.yaml` and restart:

```bash
sudo systemctl restart ueba
```

## Run (manual)

```bash
sudo python3 main.py --config config/config.yaml
```

The daemon will:
1. Verify it runs as root.
2. Load enabled eBPF monitors.
3. Start polling perf buffers.
4. Write events as JSON lines to the configured log path.

Stop with `Ctrl+C` or `SIGTERM`.

## Service Operations

If `events.log` is missing right after startup, rerun the installer from this update; it now pre-creates `/var/log/ueba/events.log` and the daemon also writes a startup JSON event immediately.


```bash
sudo systemctl status ueba
sudo journalctl -u ueba -f
sudo tail -f /var/log/ueba/events.log
```

## Test Plan in VirtualBox

After service starts, generate activity from another terminal:

```bash
# Exec + file events
ls -la /tmp
cat /etc/hosts

# Network events
curl -I https://example.com
nc -l 127.0.0.1 9001

# Privilege events (if permitted in your environment)
sudo -k
sudo true
```

Then confirm events arrive:

```bash
sudo tail -n 50 /var/log/ueba/events.log
```

## Example Output

```json
{"@timestamp":"2025-02-18T10:15:30.123+00:00","event_type":"execve","pid":1234,"uid":1000,"comm":"bash","filename":"/bin/ls"}
{"@timestamp":"2025-02-18T10:15:31.456+00:00","event_type":"connect","pid":5678,"uid":1000,"comm":"curl","saddr":"192.168.1.5","daddr":"93.184.216.34","sport":34567,"dport":80,"protocol":"TCP","family":2}
```

## Notes on Safety and Compatibility

- eBPF programs are bounded/simple and intended to pass verifier constraints.
- If a given probe cannot attach on the current kernel, the loader logs a warning and continues running remaining monitors.
- The project is intentionally a starter implementation and should be hardened before production rollout.

## Quick Validation

Run syntax checks:

```bash
python3 -m compileall main.py ueba
```

Then run daemon as root and generate events (e.g., `ls`, `curl`, opening files) to confirm log output in `/var/log/ueba/events.log`.
