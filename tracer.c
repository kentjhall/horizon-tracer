/*
 * Hooking into Horizon task activity using ftrace
 *
 * Based on the example at https://github.com/ilammy/ftrace-hook
 *
 * Copyright (c) 2022 Kent Hall
 */

#define pr_fmt(fmt) "horizon tracer: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <../kernel/sched/sched.h>

#include "overrides.h"

MODULE_DESCRIPTION("Module for Horizon task tracing");
MODULE_AUTHOR("Kent Hall <kentjhall3@hotmail.com>");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->pc = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->pc = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter(&hook->ops, (unsigned char *)hook->name, strlen(hook->name), 0);
	if (err) {
		pr_debug("ftrace_set_filter() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		ftrace_set_notrace(&hook->ops, (unsigned char *)hook->name, strlen(hook->name), 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_notrace(&hook->ops, (unsigned char *)hook->name, strlen(hook->name), 0);
	if (err) {
		pr_debug("ftrace_set_notrace() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#if !defined(CONFIG_HORIZON)
#error This is for Horizon Linux
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static inline void pre_hsys(const char *name, u64 reg0, u64 reg1, u64 reg2,
		u64 reg3, u64 reg4, u64 reg5)
{
	pr_info("[0x%x] (%d) ==> %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
			current->hzn_thread_handle, current->hzn.priority, name,
			reg0, reg1, reg2, reg3, reg4, reg5);
}

static inline void post_hsys(const char *name, long ret, u64 out)
{
	pr_info("[0x%x] (%d) ==> %s() = 0x%lx, 0x%llx\n", current->hzn_thread_handle,
			current->hzn.priority, name, ret, out);
}

#undef __SYSCALL
#define __SYSCALL(nr, name)									\
	__weak long override_ ## name(struct pt_regs *regs)					\
	{											\
		return real_ ## name(regs);							\
	}											\
	asmlinkage long (*real_ ## name)(struct pt_regs *regs);					\
	static asmlinkage long fh_ ## name(struct pt_regs *regs)				\
	{											\
		long ret;									\
												\
		pre_hsys(#name, regs->regs[0], regs->regs[1], regs->regs[2],			\
			 regs->regs[3], regs->regs[4], regs->regs[5]);				\
												\
		ret = override_ ## name(regs);							\
												\
		post_hsys(#name, ret, regs->regs[1]);						\
												\
		return ret;									\
	}
#include <asm/horizon/unistd.h>
#undef __SYSCALL

static struct task_struct *(*real_pick_next_task_horizon)(struct rq *rq);
static struct task_struct *fh_pick_next_task_horizon(struct rq *rq)
{
	struct task_struct *picked;
	struct sched_hzn_entity *hzn_curr = rq->hzn.curr;

	picked = real_pick_next_task_horizon(rq);
	if (picked && &picked->hzn != hzn_curr)
		pr_info("[0x%x] (%d) ==> picked for CPU %d\n",
			picked->hzn_thread_handle, picked->hzn.priority,
			rq->cpu);

	return picked;
}

static struct task_struct *(*real_enqueue_task_horizon)(struct rq *rq, struct task_struct *p, int flags);
static struct task_struct *fh_enqueue_task_horizon(struct rq *rq, struct task_struct *p, int flags)
{
	pr_info("[0x%x] (%d) ==> enqueue CPU %d\n",
		p->hzn_thread_handle, p->hzn.priority, rq->cpu);

	return real_enqueue_task_horizon(rq, p, flags);
}

static struct task_struct *(*real_dequeue_task_horizon)(struct rq *rq, struct task_struct *p, int flags);
static struct task_struct *fh_dequeue_task_horizon(struct rq *rq, struct task_struct *p, int flags)
{
	const char *info = "";
	if (rq->hzn.curr == &p->hzn) {
		if (p->hzn.state == HZN_SWITCHABLE)
			info = " (defer switch)";
		if (unlikely(READ_ONCE(p->__state) == TASK_DEAD))
			info = " (defer dead)";
	}
	pr_info("[0x%x] (%d) ==> dequeue CPU %d%s\n",
		p->hzn_thread_handle, p->hzn.priority, rq->cpu, info);

	return real_dequeue_task_horizon(rq, p, flags);
}

static int (*real_balance_horizon)(struct rq *rq, struct task_struct *p, struct rq_flags *rf);
static int fh_balance_horizon(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
	unsigned long running = rq->hzn.nr_running;
	int ret = real_balance_horizon(rq, p, rf);
	if (rq->hzn.nr_running != running)
		pr_info("scheduler pulled %ld tasks to CPU %d\n", rq->hzn.nr_running - running, rq->cpu);
	return ret;
}

#define SYSCALL_NAME(name) ("__arm64_" name)

#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),		\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook hooks[] = {
#define __SYSCALL(nr, name) \
	HOOK(SYSCALL_NAME(#name), fh_ ## name, &real_ ## name),
#include <asm/horizon/unistd.h>
#undef __SYSCALL
	HOOK("pick_next_task_horizon", fh_pick_next_task_horizon, &real_pick_next_task_horizon),
	HOOK("enqueue_task_horizon", fh_enqueue_task_horizon, &real_enqueue_task_horizon),
	HOOK("dequeue_task_horizon", fh_dequeue_task_horizon, &real_dequeue_task_horizon),
	HOOK("balance_horizon", fh_balance_horizon, &real_balance_horizon),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);
