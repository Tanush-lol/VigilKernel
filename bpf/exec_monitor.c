#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define ARGSIZE 128

struct exec_event_t {
    u64 ts_ns;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

char LICENSE[] = "GPL";
