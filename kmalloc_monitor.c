// kmalloc_monitor.c
// Build: make
// Usage:
//   sudo insmod kmalloc_monitor.ko
//   sudo cat /dev/kmmon          # will print allocation/free events in realtime
//   sudo rmmod kmalloc_monitor

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

static struct event *ring;
static unsigned int ring_head; // next write index
static unsigned int ring_tail; // next read index
static unsigned int ring_count;
static spinlock_t ring_lock;
static wait_queue_head_t ring_wq;

static struct kprobe kp_kmalloc;
static struct kprobe kp_kfree;

/* Helper to push a formatted event into ring buffer */
static void push_event(const char *fmt, ...)
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
    ring[ring_head].buf[len] = '\n'; // newline-terminate
    ring[ring_head].buf[len+1] = '\0';

    ring_head = (ring_head + 1) & (RING_SIZE - 1);
    if (ring_count < RING_SIZE)
        ring_count++;
    else {
        // overwrite oldest
        ring_tail = (ring_tail + 1) & (RING_SIZE - 1);
    }

    spin_unlock_irqrestore(&ring_lock, flags);
    wake_up_interruptible(&ring_wq);
    va_end(args);
}

/* kprobe pre-handler for __kmalloc
 * On x86_64 first arg in regs->di, on arm64 regs->regs[0] etc.
 * We'll handle x86_64 and generic fallback.
 */
static int kmalloc_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    size_t size = 0;
    unsigned long ts_ns;
    const char *comm = current->comm;
    pid_t pid = current->pid;

#ifdef CONFIG_X86
    size = (size_t) regs->di;
#elif defined(CONFIG_ARM64)
    size = (size_t) regs->regs[0];
#else
    /* Fallback attempt */
    size = (size_t) regs->di;
#endif

    ts_ns = ktime_get_ns();
    push_event("ALLOC ts=%llu pid=%d comm=%s size=%zu addr_hint=0x%lx",
               (unsigned long long)ts_ns, pid, comm, size, 0UL);
    return 0;
}

/* kprobe pre-handler for kfree */
static int kfree_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    void *ptr = NULL;
    unsigned long ts_ns;
    const char *comm = current->comm;
    pid_t pid = current->pid;

#ifdef CONFIG_X86
    ptr = (void *) regs->di;
#elif defined(CONFIG_ARM64)
    ptr = (void *) regs->regs[0];
#else
    ptr = (void *) regs->di;
#endif

    ts_ns = ktime_get_ns();
    push_event("FREE  ts=%llu pid=%d comm=%s ptr=%p",
               (unsigned long long)ts_ns, pid, comm, ptr);
    return 0;
}

/* Character device read: block until events exist, then copy one or more events */
static ssize_t kmmon_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    unsigned long flags;
    ssize_t copied = 0;
    size_t to_copy;
    int ret;

    /* Wait until there's at least one event */
    ret = wait_event_interruptible(ring_wq, ({ spin_lock_irqsave(&ring_lock, flags); int c = ring_count; spin_unlock_irqrestore(&ring_lock, flags); c > 0; }));
    if (ret)
        return ret;

    spin_lock_irqsave(&ring_lock, flags);

    if (ring_count == 0) {
        spin_unlock_irqrestore(&ring_lock, flags);
        return 0;
    }

    /* We'll copy at most one event per read to keep output stream friendly.
       You can modify to stream many entries at once. */
    to_copy = strnlen(ring[ring_tail].buf, EVENT_LEN);
    if (to_copy > count) {
        /* user buffer too small; tell them how big it must be */
        spin_unlock_irqrestore(&ring_lock, flags);
        return -EINVAL;
    }

    if (copy_to_user(buf, ring[ring_tail].buf, to_copy)) {
        spin_unlock_irqrestore(&ring_lock, flags);
        return -EFAULT;
    }

    /* advance tail */
    ring_tail = (ring_tail + 1) & (RING_SIZE - 1);
    ring_count--;
    copied = to_copy;

    spin_unlock_irqrestore(&ring_lock, flags);
    return copied;
}

static const struct file_operations kmmon_fops = {
    .owner = THIS_MODULE,
    .read = kmmon_read,
};

static struct miscdevice kmmon_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "kmmon",
    .fops = &kmmon_fops,
};

static int __init kmmon_init(void)
{
    int ret;

    if (!is_power_of_2(RING_SIZE)) {
        pr_err("RING_SIZE must be power of 2\n");
        return -EINVAL;
    }

    ring = kzalloc(sizeof(struct event) * RING_SIZE, GFP_KERNEL);
    if (!ring)
        return -ENOMEM;

    spin_lock_init(&ring_lock);
    init_waitqueue_head(&ring_wq);
    ring_head = ring_tail = ring_count = 0;

    /* Setup kprobe for __kmalloc */
    kp_kmalloc.pre_handler = kmalloc_pre_handler;
    kp_kmalloc.symbol_name = "__kmalloc";
    ret = register_kprobe(&kp_kmalloc);
    if (ret) {
        pr_warn("register_kprobe __kmalloc failed (%d). Trying kmalloc\n", ret);
        kp_kmalloc.symbol_name = "kmalloc";
        ret = register_kprobe(&kp_kmalloc);
        if (ret) {
            pr_err("register_kprobe for kmalloc variants failed (%d)\n", ret);
            goto fail_kmalloc;
        }
    }

    /* Setup kprobe for kfree */
    kp_kfree.pre_handler = kfree_pre_handler;
    kp_kfree.symbol_name = "kfree";
    ret = register_kprobe(&kp_kfree);
    if (ret) {
        pr_err("register_kprobe for kfree failed (%d)\n", ret);
        goto fail_kfree;
    }

    ret = misc_register(&kmmon_dev);
    if (ret) {
        pr_err("misc_register failed: %d\n", ret);
        goto fail_misc;
    }

    pr_info("kmalloc_monitor loaded; read events from /dev/%s\n", kmmon_dev.name);
    return 0;

fail_misc:
    unregister_kprobe(&kp_kfree);
fail_kfree:
    unregister_kprobe(&kp_kmalloc);
fail_kmalloc:
    kfree(ring);
    ring = NULL;
    return ret;
}

static void __exit kmmon_exit(void)
{
    misc_deregister(&kmmon_dev);
    unregister_kprobe(&kp_kfree);
    unregister_kprobe(&kp_kmalloc);

    if (ring)
        kfree(ring);

    pr_info("kmalloc_monitor unloaded\n");
}

module_init(kmmon_init);
module_exit(kmmon_exit);
