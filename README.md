# KernelShark Activity Logger for Linux Mint

A **kernel-level activity logger** that writes **user activity**, **device activity**, **network activity**, and **kernel trace** events to a single text file. Designed for Linux Mint (and any Debian/Ubuntu-based system).

## Features

| Category    | Source              | What is logged |
|------------|---------------------|----------------|
| **User**   | auditd + wtmp/btmp  | Logins, failed logins, execve, audit events |
| **Device** | udev (pyudev)       | USB/block/input device plug, unplug, change |
| **Network**| pyshark (tshark)    | TCP/UDP/ICMP packet summaries (IP, ports, HTTP URI) |
| **Kernel** | ftrace / trace-cmd  | Scheduler and block I/O events (or full trace for KernelShark GUI) |

## Requirements

- **Python 3.8+**
- **Linux** with:
  - `/sys/kernel/tracing` (tracefs) for kernel trace
  - **auditd** for user/audit logs (optional but recommended)
  - **tshark** (Wireshark CLI) for pyshark
  - **trace-cmd** optional, for periodic trace recording

## Install (Linux Mint / Ubuntu)

```bash
cd /home/tanush/Desktop/Claude/kernelShark
pip install -r requirements.txt
# System packages (for pyshark and trace-cmd)
sudo apt install tshark trace-cmd
```

**Optional:** Install audit rules so more user/exec events are written to the audit log:

```bash
sudo ./scripts/setup_audit_rules.sh
sudo systemctl restart auditd
```

## Usage

**Run manually (best with sudo for full logging):**

```bash
sudo python3 main.py
```

Log file default: `config.yaml` → `log_file` (e.g. `/var/log/kernelshark_activity.log`). If the process cannot write there, it falls back to `kernelshark_activity.log` in the project directory.

**Disable specific loggers:**

```bash
sudo python3 main.py --no-network --no-kernel
```

**Override log path:**

```bash
sudo python3 main.py -o /var/log/my_activity.log
```

**As a systemd service:**

```bash
./scripts/install_service.sh
sudo systemctl enable --now kernelshark-logger
```

View log:

```bash
tail -f /var/log/kernelshark_activity.log
```

## Configuration

Edit `config.yaml`:

- **log_file** – Where to append all activity (one file with `[USER]`, `[DEVICE]`, `[NETWORK]`, `[KERNEL]` prefixes).
- **user.audit_log** – Path to `audit.log`.
- **network.interface** – e.g. `any`, `eth0`, `wlan0`.
- **network.bpf_filter** – e.g. `tcp or udp or icmp`.
- **kernel_trace.events** – ftrace events; **use_trace_cmd** – use trace-cmd periodically instead of trace_pipe.
- **device.subsystems** – udev subsystems to monitor: `input`, `block`, `usb`, `net`.

## KernelShark GUI (trace-cmd)

To capture a kernel trace and open it in **KernelShark**:

```bash
sudo ./scripts/trace_record_for_kernelshark.sh 30 /tmp/mytrace.dat
kernelshark /tmp/mytrace.dat
```

Install KernelShark (optional):

```bash
sudo apt install kernelshark
```

## Log format

Each line is:

```
YYYY-MM-DD HH:MM:SS [CATEGORY] message
```

Example:

```
2025-02-19 14:32:01 [USER] type=USER_LOGIN msg=audit(1234567890.123:456) uid=1000
2025-02-19 14:32:05 [DEVICE] action=add subsystem=usb node=/dev/bus/usb/001/002
2025-02-19 14:32:10 [NETWORK] IP 192.168.1.1 -> 192.168.1.100 | TCP 443 -> 54321
2025-02-19 14:32:15 [KERNEL] sched_switch: prev_comm=swapper/0 ...
```

## Permissions

- **User activity:** read access to `/var/log/audit/audit.log`, `/var/log/wtmp`, `/var/log/btmp` (often root).
- **Device activity:** udev monitor works as normal user.
- **Network activity:** live capture needs **root** or `CAP_NET_RAW`.
- **Kernel trace:** reading trace_pipe or running trace-cmd needs **root**.

Running `main.py` with **sudo** is recommended for full functionality.

## License

Use and modify as needed.
