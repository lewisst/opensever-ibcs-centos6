/*
 * Copyright (c) 2011 Russell Stuart, <russell-debian@stuart.id.au>
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#if _KSL < 14
#include <asm/offset.h>
#else
#include <asm/asm-offsets.h>
#endif

#include <asm/thread_info.h>

#define	PTREGS_R15	0
#define	PTREGS_R14	8
#define	PTREGS_R13	16
#define	PTREGS_R12	24
#define	PTREGS_RBP	32
#define	PTREGS_RBX	40
#define	PTREGS_R11	48
#define	PTREGS_R10	56
#define	PTREGS_R9	64
#define	PTREGS_R8	72
#define	PTREGS_RAX	80
#define	PTREGS_RCX	88
#define	PTREGS_RDX	96
#define	PTREGS_RSI	104
#define	PTREGS_RDI	112
#define	PTREGS_ORIG_RAX	120
#define	PTREGS_RIP	128
#define	PTREGS_CS	136
#define	PTREGS_EFLAGS	144
#define	PTREGS_RSP	152
#define	PTREGS_SS	160
#define	SIZEOF_PTREGS	168


/*
 * IBCS syscall entry point.
 *
 * We get here via a software interrupt, called by the trampoline installed
 * by lcall_ldt().
 */
	.text
	.align	4,0x90
	.globl	lcall_int
lcall_int:
	swapgs
	sti
	cld
	/*
	 * Set up a struct pt_regs on the stack.
	 */
	pushq	%rax
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%rax
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	/*
	 * Re-arrange the kernel and user stacks so it looks like the user
	 * did an int $0x81 directly, without the intervening lcall.
	 */
	movq	PTREGS_RSP(%rsp),%rsi
	movq	8(%rsi),%rdi		/* lcall %rip */
	movq	%rdi,PTREGS_RIP(%rsp)
	movq	16(%rsi),%rdi		/* lcall %cs */
	movq	%rdi,PTREGS_CS(%rsp)
	movq	(%rsi),%rdi		/* 7 or 27 (arg 0 to the C handler) */
	addq	$24,PTREGS_RSP(%rsp)	/* Pop the lcall off the user stack */
	movq	%rsp,%rsi		/* pt_regs (arg 1 to the C handler) */

	GET_THREAD_INFO(%rdx)		/* %rdx = struct thread_info */
	movq	8(%rdx),%rdx		/* %rdx = %rdx->exec_domain */
	movq	8(%rdx),%rdx		/* %rdx = %rdx->handler */
	callq	*%rdx

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	movq	32(%rsp),%rax		/* rax = pt_regs->rax */

	pushq	sys_ret32		/* Use kernel's normal syscall return path */
	ret

/*
 * Make a 32bit syscall to the kernel.
 */
	.align	16,0x90
	.globl	lcall_syscall
lcall_syscall:
	movq	%rdi,%rax	/* rax=arg0, arg0=arg1, arg1=arg2, ... etc */
	movq	%rsi,%rdi
	movq	%rdx,%rsi
	movq	%rcx,%rdx
	movq	%r8,%rcx
	movq	%r9,%r8
	movq	8(%rsp),%r9
	pushq	%rax		/* Lookup the syscall in 32bit syscall table */
	salq	$3,%rax
	addq	sys_tab32,%rax
	movq	(%rax),%rax
	xchg	%rax,(%rsp)

	cmpq	$2,%rax		/* __NR_IBCS_fork */
	je	_ptregscall32
	cmpq	$11,%rax	/* __NR_IBCS_execve */
	je	_ptregscall32
	ret

	/*
	 * A few entries in the kernel's sys_call table PTREGSCALL's, meaning
	 * the syscall wants a pointer to the saved interrupt frame (a struct
	 * pt_regs), and the sys_tab32 table entry points to a small block of
         * code that sets that up.  That block of code contains the real
	 * address of the kernels syscall function which is the thing we have
	 * to call.
	 */
_ptregscall32:
	xchg	%rax,(%rsp)
 	movslq	3(%rax),%r11	/* Extract OFF_syscall from lea OFF_syscall(%rip),%rax */
 	addq	$7,%rax		/* %rax=%rip following lea OFF_syscall(%rip),%rax */
 	addq	%r11,%rax	/* %rax=OFF+%rip == syscall() */
	xchg	%rax,(%rsp)
	ret

/*
 * Make a 64bit syscall to the kernel.
 */
	.align	16,0x90
	.globl	lcall_syscall64
lcall_syscall64:
	movq	%rdi,%rax	/* rax=arg0, arg0=arg1, arg1=arg2, ... etc */
	movq	%rsi,%rdi
	movq	%rdx,%rsi
	movq	%rcx,%rdx
	movq	%r8,%rcx
	movq	%r9,%r8
	movq	8(%rsp),%r9	/* Lookup the syscall in 64bit syscall table */
	pushq	%rax
	salq	$3,%rax
	addq	sys_tab64,%rax
	movq	(%rax),%rax
	xchg	%rax,(%rsp)
	ret

_ptregscall64:
	xchg	%rax,(%rsp)
 	movslq	15(%rax),%r11	/* Extract OFF_syscall from callq OFF_syscall */
 	addq	$19,%rax	/* %rax=%rip following callq OFF_syscall */
 	addq	%r11,%rax	/* %rax=OFF+%rip == syscall() */
	xchg	%rax,(%rsp)
	ret

/*
 * Initialise ourselves.  This initialisation is done from within a special
 * 32bit syscall triggered by running abi_exec.  Naturally abi_exec must be
 * the first thing run, before any syscall's are done.  It is necessary
 * to do this from within a 32bit syscall so we can use the syscall's
 * return address to find the 32bit syscall table and exit point.
 *
 * We get here via:
 *   abi_ldr runs abi_exec (a SYSV 32 bit program) -->
 *   abi_exec does a exec syscall -->
 *   sys_exec calls lcall_load_binary()  -->
 *   lcall_load_binary() calls lcall_syscall_init(entry64,entry32).
 *
 *  %rdi = Something close to the kernel's 64 bit entry point.
 *  %rsi = Return address to kernels 32bit syscall dispatch.
 */
	.globl	lcall_syscall_init
lcall_syscall_init:
	cmpq	$0,sys_tab32
	jne	9f	
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx

	/*
	 * search for the instruction "call *sys_call_table(,%rax,8)"
	 * in arch/x86/kernel/entry_64.S: ENTRY(system_call)
	 */
	movq	$512,%rcx
	movq	$-1,%rax
	movq	%rdi,%rbx
1:
	inc	%rbx
	dec	%rcx
	jz	3f
	cmpb	$255,(%rbx)
	jne	1b
	cmpb	$20,1(%rbx)
	jne	1b
	cmpb	$197,2(%rbx)
	jne	1b

	/*
	 * Extract the address of sys_call_table out of the
	 * "call *sys_call_table(,%rax,8)".  It is %rip relative.
	 */
	movl	3(%rbx),%ecx
	movq	%rsi,%rax
	sarq	$32,%rax
	salq	$32,%rax
	orq	%rcx,%rax
	movq	%rax,sys_tab64

	/*
         * search for the instruction "call *ia32_sys_call_table(,%rax,8)"
	 * in arch/x86/kernel/ia32entry.S: ENTRY(ia32_syscall)
	 */
	movq	$512,%rcx
	movq	$-1,%rax
	movq	%rsi,%rbx
	subq	$512,%rbx
2:
	inc	%rbx
	dec	%rcx
	jz	3f
	cmpb	$255,(%rbx)
	jne	2b
	cmpb	$20,1(%rbx)
	jne	2b
	cmpb	$197,2(%rbx)
	jne	2b

	/*
	 * Extract the address of ia32_sys_call_table out of the
	 * "call *ia32_sys_call_table(,%rax,8)".  It is %rip relative.
	 */
	movl	3(%rbx),%ecx
	movq	%rsi,%rax
	sarq	$32,%rax
	salq	$32,%rax
	orq	%rcx,%rax
	movq	%rax,sys_tab32

	addq	$7,%rbx
	movq	%rbx,sys_ret32

3:
	popq	%rdx
	popq	%rcx
	popq	%rbx

9:
	movq	$0,%rax
	ret

/*
 * Arrange for a function to be called on when the current syscall returns.
 *
 * %rdi = struct pt_regs*
 */
	.globl	lcall_ldt_on_syscall_return
lcall_ldt_on_syscall_return:
	movq	-8(%rdi),%rax
	movq	%rax,abi_vm86_ret
	movq	$abi_vm86,-8(%rdi)	/* Make current syscall return to abi_vm86 */
	ret

abi_vm86:
	cmpl	$0,%eax
	jl	1f
	pushq	%rax
	callq	lcall_ldt
	popq	%rax
1:
	pushq	abi_vm86_ret
	ret

	.data
sys_tab32:			/* Address of kernel's 32bit syscall table */
	.zero	8
sys_tab64:			/* Address of kernel's 64bit syscall table */
	.zero	8
sys_ret32:			/* Start of kernel's 32bit syscall exit code */
	.zero	8
abi_vm86_ret:
	.zero	8
