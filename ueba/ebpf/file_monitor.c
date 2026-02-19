/*
 * UEBA file monitor: trace open/openat (file opens, libraries loaded).
 * Tracepoint syscalls:sys_enter_openat (preferred) or kprobe.
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
 * openat(int dfd, const char *filename, int flags, ...)
 * From pt_regs: parm1=dfd, parm2=filename, parm3=flags.
 */
int trace_openat_entry(struct pt_regs *ctx)
{
    const char __user *filename = (const char __user *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;

    struct file_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = uid;
    ev.flags = (u32)flags;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    if (filename) {
        bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), filename);
    }

    file_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
