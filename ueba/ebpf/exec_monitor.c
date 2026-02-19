/*
 * UEBA exec monitor: trace execve (process execution).
 * Uses tracepoint syscalls/sys_enter_execve for reliable argument access
 * across kernel versions (4.17+ changed syscall wrapper calling convention).
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
 * Tracepoint: syscalls/sys_enter_execve
 * args->filename is the path, args->argv is the argument array.
 * This works reliably on all kernel versions without the __x64_sys wrapper issue.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;

    struct exec_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = uid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    const char *fn = args->filename;
    if (fn) {
        bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), fn);
    }

    const char *const *argv = args->argv;
    if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), argv);
        if (arg0) {
            bpf_probe_read_user_str(&ev.argv, sizeof(ev.argv), arg0);
        }
    }

    exec_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
