#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/ptrace.h>

#define SYSCALL_THRESHOLD 10
#define SYSCALL_WINDOW_NS 1000000  // 1ms

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT");
MODULE_DESCRIPTION("Interrupt Check Module using kprobe on do_syscall_64");

struct syscall_stat {
    u64 last_time;
    int count;
};

static struct syscall_stat syscall_stats[512];

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    long syscall_num = regs->orig_ax;
    u64 now = ktime_get_ns();

    if (syscall_num < 0 || syscall_num >= 512)
        return 0;

    struct syscall_stat *stat = &syscall_stats[syscall_num];

    if (now - stat->last_time < SYSCALL_WINDOW_NS) {
        stat->count++;
    } else {
        stat->count = 1;
    }

    stat->last_time = now;

    if (stat->count > SYSCALL_THRESHOLD) {
        pr_warn("interrupt_check: Suspicious syscall %ld: freq=%d\n",
                syscall_num, stat->count);
        udelay(10 + (syscall_num % 10)); // 扰动延迟
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "do_syscall_64",
    .pre_handler = handler_pre,
};

static int __init interrupt_check_init(void)
{
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("interrupt_check: failed to register kprobe\n");
        return ret;
    }
    pr_info("interrupt_check: kprobe registered on do_syscall_64\n");
    return 0;
}

static void __exit interrupt_check_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("interrupt_check: kprobe unregistered\n");
}

module_init(interrupt_check_init);
module_exit(interrupt_check_exit);