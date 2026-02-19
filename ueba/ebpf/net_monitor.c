/*
 * UEBA network monitor: TCP connect, and optionally bind/listen/accept.
 * Connect: kprobe tcp_v4_connect / tcp_v6_connect; on return read sk from map.
 * Extracts: PID, UID, comm, saddr, daddr, sport, dport, protocol (TCP).
 * Bind/listen: kprobe on inet_bind / inet_listen for listening ports.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#define TASK_COMM_LEN 16

/* Event types: 1=connect, 2=accept, 3=bind, 4=listen */
struct net_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 event_type;   /* 1=connect, 2=accept, 3=bind, 4=listen */
    u32 saddr;       /* IPv4 only in this struct; IPv6 can be extended */
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(net_events);

BPF_HASH(sk_connect_tmp, u32, struct sock *);

/* Stash sk on connect entry; on return read addresses and submit */
int trace_tcp_v4_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    sk_connect_tmp.update(&tid, &sk);
    return 0;
}

int trace_tcp_v4_connect_return(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct sock **skpp = sk_connect_tmp.lookup(&tid);
    if (!skpp) return 0;
    if (ret != 0) {
        sk_connect_tmp.delete(&tid);
        return 0;
    }

    struct sock *skp = *skpp;
    struct net_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    ev.event_type = 1; /* connect */
    ev.saddr = skp->__sk_common.skc_rcv_saddr;
    ev.daddr = skp->__sk_common.skc_daddr;
    ev.sport = skp->__sk_common.skc_num;
    ev.dport = skp->__sk_common.skc_dport;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    net_events.perf_submit(ctx, &ev, sizeof(ev));
    sk_connect_tmp.delete(&tid);
    return 0;
}

/* inet_listen: socket transitions to LISTEN; we get sk. */
int trace_inet_listen(struct pt_regs *ctx, struct sock *sk, int backlog)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct net_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    ev.event_type = 4; /* listen */
    ev.saddr = sk->__sk_common.skc_rcv_saddr;
    ev.daddr = 0;
    ev.sport = sk->__sk_common.skc_num;
    ev.dport = 0;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    net_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

/* inet_bind: bind() called; we get sk. */
int trace_inet_bind(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct net_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFFULL;
    ev.event_type = 3; /* bind */
    ev.saddr = sk->__sk_common.skc_rcv_saddr;
    ev.daddr = 0;
    ev.sport = sk->__sk_common.skc_num;
    ev.dport = 0;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    net_events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
