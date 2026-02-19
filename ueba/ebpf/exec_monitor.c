/*
 * UEBA exec monitor: trace execve (process execution).
 * Extracts: PID, UID, comm, full filename, optional argv prefix.
 * Submit event via BPF_PERF_OUTPUT to user space.
 * BCC compiles and loads this.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256
#define ARGV_LEN 256

struct exec_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    char argv[ARGV_LEN];
};
BPF_PERF_OUTPUT(exec_events);

/*
 * Syscall entry for execve. Arguments from pt_regs: arg1 = filename, arg2 = argv.
 * Attach as kprobe to __x64_sys_execve or sys_execve (BCC picks correct symbol).
 */
int trace_execve_entry(struct pt_regs *ctx)
{
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    const char __user *const __user *argv = (const char __user *const __user *)PT_REGS_PARM2(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;

    struct exec_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = uid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    if (filename) {
        bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), filename);
    }

    if (argv) {
        const char __user *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), argv);
        if (arg0) {
            bpf_probe_read_user_str(&ev.argv, sizeof(ev.argv), arg0);
        }
    }

    exec_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
