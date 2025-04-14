
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define SYSCALL_MONITOR_WINDOW_NS 1000000  // 1ms窗口
#define SYSCALL_FREQ_THRESHOLD    10       // 阈值：每毫秒不超过10次

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT");
MODULE_DESCRIPTION("Kprobe-based syscall interrupt security checker");
MODULE_VERSION("0.1");

struct syscall_stat {
    u64 last_time;
    int count;
};

static struct syscall_stat syscall_stats[512]; // 支持前512个系统调用

static struct kprobe kp = {
    .symbol_name = "syscall_call", // 对应 int 0x80 的入口
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    u64 now = ktime_get_ns();
    long syscall_num = regs->orig_ax;

    if (syscall_num < 0 || syscall_num >= 512)
        return 0;

    struct syscall_stat *stat = &syscall_stats[syscall_num];

    if (now - stat->last_time < SYSCALL_MONITOR_WINDOW_NS) {
        stat->count++;
    } else {
        stat->count = 1;
        stat->last_time = now;
    }

    if (stat->count > SYSCALL_FREQ_THRESHOLD) {
        pr_warn("[interrupt_check] Suspicious syscall %ld: freq=%d
", syscall_num, stat->count);
        udelay(10 + (syscall_num % 10)); // 扰动延迟
    }

    return 0;
}

static int __init interrupt_check_init(void)
{
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("interrupt_check module loaded. Monitoring int 0x80 (syscall_call).\n");
    return 0;
}

static void __exit interrupt_check_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("interrupt_check module unloaded.\n");
}

module_init(interrupt_check_init)
module_exit(interrupt_check_exit)
