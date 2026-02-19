# UEBA – User and Entity Behavior Analytics (Kernel-Level)

Kernel-level **User and Entity Behavior Analytics** for Linux Mint and other Debian-based systems. It monitors **process execution**, **file opens**, **network** (connect/bind/listen), **user logins**, **audit** events, and **block/USB devices** (e.g. external drives, data migration), and writes **JSON lines** to a rotating log file.

## Features

| Monitor | Source | Events |
|--------|--------|--------|
| **Exec** | eBPF (BCC) | `execve`: PID, UID, comm, full filename, argv |
| **File** | eBPF (BCC) | `openat`: PID, UID, filename, flags (binaries, libraries) |
| **Network** | eBPF (BCC) | TCP connect, bind, listen: PID, UID, saddr, daddr, sport, dport |
| **User session** | User-space | Logins (wtmp), failed logins (btmp) |
| **Audit** | User-space | Tail audit log: auth, execve, module load, etc. |
| **Block/device** | udev (pyudev) | USB/block add/remove (disks, external drives) |

- **Application/tools executed:** from **exec** (filename, argv) and **audit** (execve).
- **Browser activity:** reflected via **exec** (browser process name), **network** (outgoing connections, ports), and **file** (opens). For URL-level tracking you would need additional tooling (e.g. HTTP/TLS inspection).
- **Hard drive / external drives:** **block** and **device** events (udev) show when block/USB devices are added or removed (e.g. external drives connected for data migration).

All events are written to **one log file** in **JSON lines** format, with rotation (size + backup count).

## Requirements

- **Linux kernel 5.4+** (eBPF, tracepoints)
- **Root** (for eBPF, `/var/log`, audit)
- **Python 3.8+**
- **BCC** (BPF Compiler Collection) for eBPF monitors; optional if you run with `--no-ebpf`

## Install (Linux Mint / Ubuntu / Debian)

### 1. System packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip linux-headers-$(uname -r)
# BCC for eBPF (recommended)
sudo apt install -y python3-bpfcc bpfcc-tools
```

If `python3-bpfcc` is not available, see [BCC install](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

### 2. Python dependencies

```bash
cd /path/to/kernelShark/ueba
pip3 install --user PyYAML pyudev
# Or with sudo:
# sudo pip3 install PyYAML pyudev
```

### 3. Optional: use Makefile

```bash
make install-deps
```

## Run

**Must run as root** (eBPF and log/audit access):

```bash
cd /path/to/kernelShark/ueba
sudo python3 main.py
```

Or from repo root:

```bash
sudo python3 ueba/main.py -c ueba/config/config.yaml
```

**Without eBPF** (only user-space: wtmp, btmp, audit tail, udev):

```bash
sudo python3 main.py --no-ebpf
```

**Config path:**

```bash
sudo python3 main.py --config /etc/ueba/config.yaml
```

## Log file

- **Default:** `/var/log/ueba/events.log`
- **Rotation:** 10 MB max size, 5 backup files (configurable in `config/config.yaml`)
- If the daemon cannot write to `/var/log/ueba/`, it falls back to `ueba/ueba_events.log` in the project directory.

**Example lines:**

```json
{"@timestamp": "2025-02-19T12:00:00.123Z", "event_type": "execve", "pid": 1234, "uid": 1000, "comm": "bash", "filename": "/usr/bin/ls", "argv": ["ls", "-l"]}
{"@timestamp": "2025-02-19T12:00:01.456Z", "event_type": "connect", "pid": 5678, "uid": 1000, "comm": "curl", "saddr": "192.168.1.5", "daddr": "93.184.216.34", "sport": 34567, "dport": 80, "protocol": "TCP"}
{"@timestamp": "2025-02-19T12:00:02.789Z", "event_type": "device", "device_action": "add", "subsystem": "block", "devnode": "/dev/sdb1", "id_fs_label": "USB_DRIVE"}
```

## Configuration

Edit `config/config.yaml`:

- **logging.path** – Log file path
- **logging.max_bytes**, **backup_count** – Rotation
- **monitors.exec / file / network / user_session / block / audit** – Enable/disable each monitor
- **exec_filter.path_prefix** – Limit exec events by path (optional)
- **file_filter.path_prefix**, **log_libraries** – File open filters
- **network_filter.include_connect / include_bind / include_listen**
- **user_session** – wtmp, btmp paths and poll interval
- **audit.log_path**, **poll_interval_sec**
- **block.udev_subsystems** – e.g. `["block", "usb"]`

## Project layout

```
ueba/
├── config/
│   └── config.yaml
├── ebpf/
│   ├── exec_monitor.c
│   ├── file_monitor.c
│   ├── net_monitor.c
│   └── load_bpf.py       # BCC loaders
├── sources/
│   ├── user_session.py   # wtmp/btmp
│   ├── audit_tail.py     # audit log tail
│   └── block_udev.py     # udev block/USB
├── config_parser.py
├── logger.py             # JSON lines + RotatingFileHandler
├── utils.py
├── main.py
├── Makefile
└── README.md
```

## Error handling

- If BCC is missing or eBPF load fails, the daemon still runs with user-space sources; use `--no-ebpf` to disable eBPF entirely.
- If a tracepoint/kprobe symbol is missing (e.g. different kernel), that monitor is skipped; others continue.
- Run as root and ensure `/var/log/ueba/` exists (or create it) for the default log path.

## Relation to KernelShark activity logger

This UEBA daemon is the **eBPF + JSON** counterpart to the simpler **KernelShark activity logger** in the parent directory. That one writes plain-text lines to a single log; this one writes **JSON lines** with rotation and focuses on **exec, file, network, logins, audit, and block/device** for behavior analytics. You can run both: UEBA for structured analytics, the other for human-readable tailing.
