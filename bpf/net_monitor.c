#include <linux/net.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ptrace.h>

#define EVENT_CONNECT 1
#define EVENT_ACCEPT 2
#define EVENT_BIND 3
#define EVENT_LISTEN 4

struct net_event_t {
    u64 ts_ns;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    u8 protocol;
    u8 event_type;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static int submit_sock_event(struct pt_regs *ctx, struct sock *sk, u8 event_type) {
    if (sk == NULL) {
        return 0;
    }

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }

    struct net_event_t event = {};
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.family = family;
    event.protocol = IPPROTO_TCP;
    event.event_type = event_type;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    return submit_sock_event(ctx, sk, EVENT_CONNECT);
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    return submit_sock_event(ctx, newsk, EVENT_ACCEPT);
}

int kprobe__inet_bind(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr, int addr_len) {
    struct sock *sk = sock->sk;
    return submit_sock_event(ctx, sk, EVENT_BIND);
}

int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog) {
    struct sock *sk = sock->sk;
    return submit_sock_event(ctx, sk, EVENT_LISTEN);
}

char LICENSE[] = "GPL";
