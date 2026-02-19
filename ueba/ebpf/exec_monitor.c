/*
 * UEBA exec monitor: trace execve (process execution).
 * Uses tracepoint syscalls/sys_enter_execve for reliable argument access.
 * Uses BPF_PERCPU_ARRAY for the event struct since it exceeds the
 * 512-byte BPF stack limit (struct is 544 bytes).
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

/* Per-CPU scratch space to avoid blowing the 512-byte stack limit */
BPF_PERCPU_ARRAY(exec_heap, struct exec_event_t, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 zero = 0;
    struct exec_event_t *ev = exec_heap.lookup(&zero);
    if (!ev)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = pid_tgid >> 32;
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    /* Zero out the string fields to avoid stale data from previous events */
    __builtin_memset(&ev->filename, 0, FILENAME_LEN);
    __builtin_memset(&ev->argv, 0, ARGV_LEN);

    const char *fn = args->filename;
    if (fn) {
        bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), fn);
    }

    const char *const *argv = args->argv;
    if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), argv);
        if (arg0) {
            bpf_probe_read_user_str(&ev->argv, sizeof(ev->argv), arg0);
        }
    }

    exec_events.perf_submit(args, ev, sizeof(*ev));
    return 0;
}
