#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT (example)");
MODULE_DESCRIPTION("Realtime kmalloc/kfree monitor via /dev/kmmon (kprobes)");
MODULE_VERSION("0.5");

#define EVENT_LEN 256
#define RING_SIZE 1024

struct event {
    char buf[EVENT_LEN];
};

static struct event* ring;
static unsigned int ring_head;
static unsigned int ring_tail;
static unsigned int ring_count;
static spinlock_t ring_lock;
static wait_queue_head_t ring_wq;

static struct kprobe kp_kmalloc;
static struct kprobe kp_kfree;

static void push_event(const char* fmt, ...)
{
    va_list args;
    unsigned long flags;
    int len;

    va_start(args, fmt);

    spin_lock_irqsave(&ring_lock, flags);

    if (!ring) {
        spin_unlock_irqrestore(&ring_lock, flags);
        va_end(args);
        return;
    }

    len = vscnprintf(ring[ring_head].buf, EVENT_LEN - 1, fmt, args);
    ring[ring_head].buf[len] = '\n';
    ring[ring_head].buf[len + 1] = '\0';

    ring_head = (ring_head + 1) & (RING_SIZE - 1);
    if (ring_count < RING_SIZE)
        ring_count++;
    else {
        ring_tail = (ring_tail + 1) & (RING_SIZE - 1);
    }

    spin_unlock_irqrestore(&ring_lock, flags);
    wake_up_interruptible(&ring_wq);
    va_end(args);
}

static int kmalloc_pre_handler(struct kprobe* p, struct pt_regs* regs)
{
    size_t size = 0;
    unsigned long ts_ns;
    const char* comm = current->comm;
    pid_t pid = current->pid;

#ifdef CONFIG_X86
    size = (size_t)regs->di;
#elif defined(CONFIG_ARM64)
    size = (size_t)regs->regs[0];
#else
    size = (size_t)regs->di;
#endif

    ts_ns = ktime_get_ns();
    push_event("ALLOC ts=%llu pid=%d comm=%s size=%zu addr_hint=0x%lx",
        (unsigned long long)ts_ns, pid, comm, size, 0UL);
    return 0;
}

static int kfree_pre_handler(struct kprobe* p, struct pt_regs* regs)
{
    void* ptr = NULL;
    unsigned long ts_ns;
    const char* comm = current->comm;
    pid_t pid = current->pid;

#ifdef CONFIG_X86
    ptr = (void*)regs->di;
#elif defined(CONFIG_ARM64)
    ptr = (void*)regs->regs[0];
