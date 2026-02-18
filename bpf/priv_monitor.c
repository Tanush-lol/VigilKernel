#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define PATHSIZE 256
#define EVENT_SETUID 1
#define EVENT_CAPSET 2
#define EVENT_MODULE_LOAD 3

struct priv_event_t {
    u64 ts_ns;
    u32 pid;
    u32 uid;
    u8 event_type;
    u32 arg0;
    char comm[TASK_COMM_LEN];
    char detail[PATHSIZE];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct priv_event_t event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.event_type = EVENT_SETUID;
    event.arg0 = args->uid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_capset) {
    struct priv_event_t event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.event_type = EVENT_CAPSET;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(module, module_load) {
    struct priv_event_t event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.event_type = EVENT_MODULE_LOAD;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.detail, sizeof(event.detail), args->name);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

char LICENSE[] = "GPL";
