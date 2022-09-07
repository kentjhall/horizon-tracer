#ifndef _OVERRIDES_H
#define _OVERRIDES_H

#include <linux/syscalls.h>

#undef __SYSCALL
#define __SYSCALL(nr, name)						\
	long override_ ## name(struct pt_regs *regs);			\
	extern asmlinkage long (*real_ ## name)(struct pt_regs *regs);
#include <asm/horizon/unistd.h>
#undef __SYSCALL

#define REGS_TO_ARGS(x, ...)					\
	__MAP(x,__SC_ARGS					\
	      ,,regs->regs[0],,regs->regs[1],,regs->regs[2]	\
	      ,,regs->regs[3],,regs->regs[4],,regs->regs[5])

#define OVERRIDEx(x, name, ...)							\
	static long __override_ ## name(struct pt_regs *__regs,			\
			__MAP(x,__SC_LONG,__VA_ARGS__));			\
	static long ____override_ ## name(struct pt_regs *__regs,		\
			__MAP(x,__SC_DECL,__VA_ARGS__));			\
	long override_hsys_ ## name(struct pt_regs *regs)			\
	{									\
		return __override_ ## name(regs, REGS_TO_ARGS(x, __VA_ARGS__));	\
	}									\
	static long __override_ ## name(struct pt_regs *__regs,			\
			__MAP(x,__SC_LONG,__VA_ARGS__))				\
	{									\
		return ____override_ ## name(__regs,				\
				__MAP(x,__SC_CAST,__VA_ARGS__));		\
	}									\
	static long ____override_ ## name(struct pt_regs *__regs,		\
			__MAP(x,__SC_DECL,__VA_ARGS__))

#define OVERRIDE0(name, ...)							\
	static long __override_ ## name(struct pt_regs *__regs);		\
	long override_hsys_ ## name(struct pt_regs *regs)			\
	{									\
		return __override_ ## name(regs);				\
	}									\
	static long __override_ ## name(struct pt_regs *__regs)
#define OVERRIDE1(name, ...) OVERRIDEx(1, name, __VA_ARGS__)
#define OVERRIDE2(name, ...) OVERRIDEx(2, name, __VA_ARGS__)
#define OVERRIDE3(name, ...) OVERRIDEx(3, name, __VA_ARGS__)
#define OVERRIDE4(name, ...) OVERRIDEx(4, name, __VA_ARGS__)
#define OVERRIDE5(name, ...) OVERRIDEx(5, name, __VA_ARGS__)
#define OVERRIDE6(name, ...) OVERRIDEx(6, name, __VA_ARGS__)

#define REAL(name) \
	real_hsys_ ## name(__regs)

#define OUT __regs->regs[1]

#endif
