/*
 * UEBA file monitor: trace openat (file opens, libraries loaded).
 * Uses tracepoint syscalls/sys_enter_openat for reliable argument access
 * across kernel versions (4.17+ changed syscall wrapper calling convention).
 * Extracts: PID, UID, comm, filename, flags.
 * Optionally filter by path prefix in user space; here we capture all.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

struct file_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
};
BPF_PERF_OUTPUT(file_events);

/*
 * Tracepoint: syscalls/sys_enter_openat
 * args->filename is the path, args->flags is the open flags.
 * This works reliably on all kernel versions.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;

    struct file_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = uid;
    ev.flags = (u32)args->flags;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    const char *fn = args->filename;
    if (fn) {
        bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), fn);
    }

    file_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
