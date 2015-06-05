/*
 * Copyright (c) 2000,2001 Christoph Hellwig.
 * Copyright (c) 2001 Caldera Deutschland GmbH.
 * All rights resered.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Lowlevel handler for lcall7-based syscalls.
 */
#include "../include/util/i386_std.h"
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/desc.h>
#include <asm/msr.h>
/*
#ifdef	CONFIG_XEN
#include <asm/xen/hypervisor.h>
#include <xen/page.h>
#include <xen/events.h>
#endif
*/
#include "../include/abi_reg.h"
#include "../include/util/errno.h"
#include "../include/util/trace.h"
#include "../include/util/sysent.h"

MODULE_AUTHOR("Christoph Hellwig");
MODULE_DESCRIPTION("Lowlevel handler for lcall7-based syscalls");
MODULE_LICENSE("GPL");
MODULE_INFO(supported,"yes");
MODULE_INFO(bugreport,"agon04@users.sourceforge.net");

static char *ExeFlags = NULL;
module_param(ExeFlags, charp, 0);
MODULE_PARM_DESC(ExeFlags,"Personality Flags List");

static int Amd64vector = 127;
module_param(Amd64vector, int, 0);
MODULE_PARM_DESC(Amd64vector,"Interrupt vector to use on amd64");

extern asmlinkage int lcall_syscall_init(unsigned long, unsigned long);

#if _KSL > 26
DECLARE_RWSEM(uts_sem);
EXPORT_SYMBOL(uts_sem);
#endif

static void get_args(int args[], struct pt_regs *regs, int of, int n)
{
	int i;

	for (i = 0; i < n; i++)
		get_user(args[i], ((unsigned int *)_SP(regs)) + (i+of));
}

/*
 *	lcall7_syscall    -    indirect syscall for the lcall7 entry point
 *
 *	@regs:		saved user registers
 *
 *	This function implements syscall(2) in kernelspace for the lcall7-
 *	based personalities.
 */
typedef __attribute__((regparm(0))) void (*lc_handler_t)(int, struct pt_regs *);

int lcall7_syscall(struct pt_regs *regs)
{
	lc_handler_t h_lcall;
	__get_user(_AX(regs), ((unsigned long *)_SP(regs))+1);

	++_SP(regs);
	h_lcall = (lc_handler_t)current_thread_info()->exec_domain->handler;
	(h_lcall)(-1,regs);
	--_SP(regs);

	return 0;
}

/**
 *	lcall7_dispatch    -    handle lcall7-based syscall entry
 *
 *	@regs:		saved user registers
 *	@ap:		syscall table entry
 *	@off:		argument offset
 *
 *	This function handles lcall7-based syscalls after the personality-
 *	specific rountine selected the right syscall table entry.
 */

void lcall7_dispatch(struct pt_regs *regs, struct sysent *ap, int off)
{
	short nargs = ap->se_nargs;
	unsigned long iSysFunc = (unsigned long)ap->se_syscall;
	int args[8], error;

	if (!ap->se_syscall) /* XXX kludge XXX */
		nargs = Unimpl;

	if (nargs <= ARRAY_SIZE(args))
		get_args(args, regs, off, nargs);

#if defined(CONFIG_ABI_TRACE)
	if (abi_traced(ABI_TRACE_API)) {
		if (nargs == Spl)
			get_args(args, regs, off, strlen(ap->se_args));
		plist(ap->se_name, ap->se_args, args);
	}
#endif

	if (iSysFunc > 0 && iSysFunc < 512) {
		error = lcall_syscall(iSysFunc,args[0],args[1],args[2],args[3],args[4],args[5],args[6]);
	}
	else switch (nargs) {
		case Fast:
			SYSCALL_PREGS(ap->se_syscall, regs);
			goto show_signals;
		case Spl:
			error = SYSCALL_PREGS(ap->se_syscall, regs);
			break;
		case 0:
			error = SYSCALL_VOID(ap->se_syscall);
			break;
		case 1:
			error = SYSCALL_1ARG(ap->se_syscall, args);
			break;
		case 2:
			error = SYSCALL_2ARG(ap->se_syscall, args);
			break;
		case 3:
			error = SYSCALL_3ARG(ap->se_syscall, args);
			break;
		case 4:
			error = SYSCALL_4ARG(ap->se_syscall, args);
			break;
		case 5:
			error = SYSCALL_5ARG(ap->se_syscall, args);
			break;
		case 6:
			error = SYSCALL_6ARG(ap->se_syscall, args);
			break;
		case 7:
			error = SYSCALL_7ARG(ap->se_syscall, args);
			break;
		default:
#if defined(CONFIG_ABI_TRACE)
			abi_trace(ABI_TRACE_UNIMPL,
				"Unsupported ABI function 0x%lx (%s)\n",
				_AX(regs), ap->se_name);
#endif
			error = -ENOSYS;
	}

	if (error > -ENOIOCTLCMD && error < 0) {
		set_error(regs, iABI_errors(-error));

#if defined(CONFIG_ABI_TRACE)
		abi_trace(ABI_TRACE_API,
			"%s error return %d/%ld\n",
			ap->se_name, error, _AX(regs));
#endif
	} else {
		clear_error(regs);
		set_result(regs, error);

#if defined(CONFIG_ABI_TRACE)
		abi_trace(ABI_TRACE_API,
			"%s returns %ld (edx:%ld)\n",
			ap->se_name, _AX(regs), _DX(regs));
#endif
	}

show_signals:
#if defined(CONFIG_ABI_TRACE)
	if (signal_pending(current) && abi_traced(ABI_TRACE_SIGNAL)) {
		unsigned long signr;

		signr = current->pending.signal.sig[0] &
			~current->blocked.sig[0];
		if (!signr)
			signr = current->signal->shared_pending.signal.sig[0] &
				~current->blocked.sig[0];

		__asm__("bsf %1,%0\n\t"
				:"=r" (signr)
				:"0" (signr));

		__abi_trace("SIGNAL %lu, queued 0x%08lx\n",
			signr+1,
			current->pending.signal.sig[0] | current->signal->shared_pending.signal.sig[0]);
	}
#endif
}

/*------------------------------------------------------*/
static char *abi_perlist = (char *)0;

unsigned long
abi_personality(char *pPath)
{
	char *pName, *s, buf[128]; unsigned long l; int len;

	if (!abi_perlist) return 0;

	if( strncpy_from_user(buf,pPath,128) < 0 ) return 0;

	pName = buf; s = buf;
	while (s[0]!='\0') { if (s[0]=='/') pName = s+1; s++; }
	len = s - pName + 1;

	s = abi_perlist;
	l = 0;
	while (s[0] != '\0') {
		if ( memcmp(s+1,pName,len) == 0 ) {
			s = s + (int)(s[0]) - sizeof(long);
			l = *( (unsigned long *)s );
			break;
		}
		s = s + (int)(s[0]);
	}
	return l;
}
			
#define ELF_HEAD	0x464C457F
#define ELF_UXW7	0x314B4455
#define ELF_OSR5	0x3552534F
#define ELF_SVR4	0x34525653
#define ELF_X286	0x36383258

static asmlinkage void
linux_lcall7(int segment, struct pt_regs *regs)
{
	char buf[40];
	int iFD;
	mm_segment_t fs;
	u_int *lMarks;
	long lPers, nPers;
	lc_handler_t h_pers;

#if defined(CONFIG_ABI_TRACE)
	if ( (_OAX(regs) & 0xFF00) == 0xFF00 ) {
		_AX(regs) = abi_trace_flg;
		abi_trace_flg = _OAX(regs) & 0x00FF;
		printk("ABI Trace Flag: %02lX\n",(ulong)abi_trace_flg);
		return;
	}
#endif
	lPers = PER_SVR4;
	if (segment == 0x27) lPers = PER_SOLARIS;

	sprintf(buf,"/proc/%d/exe",current->pid);
	fs=get_fs(); set_fs(get_ds());
	iFD=SYS_NATIVE(open,buf,0,0);
	SYS_NATIVE(read,iFD,buf,40);
	SYS_NATIVE(close,iFD);
	set_fs(fs);
	lMarks = (u_int *)buf;
	if (lMarks[0] == ELF_HEAD) {
		if (lMarks[9] == ELF_UXW7) lPers = PER_UW7;
		if (lMarks[9] == ELF_OSR5) lPers = PER_OSR5;
		if (lMarks[9] == ELF_X286) lPers = PER_XENIX;
	}
	fs=get_fs(); set_fs(get_ds());
	nPers = abi_personality(current->comm);
	set_fs(fs);
	if (nPers != 0 && nPers != current->personality) lPers = nPers;
	if ( (lPers & 0xFF) == (current->personality & 0xFF) ) set_personality(0);
	set_personality(lPers);

	if(current_thread_info()->exec_domain->handler == (handler_t)linux_lcall7) {
#if defined(CONFIG_ABI_TRACE)
	abi_trace(ABI_TRACE_UNIMPL,"Unable to find Domain %ld\n",lPers&0xFF);
#endif
		_IP(regs) = 0;	/* SegFault please :-) */
		return;
	}
#if defined(CONFIG_ABI_TRACE)
	abi_trace(ABI_TRACE_UNIMPL,"Personality %08lX assigned\n",lPers);
#endif
	if (lPers & MMAP_PAGE_ZERO) { 		/* Better Late than Never */
		down_write(&current->mm->mmap_sem);
			do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE | MAP_32BIT, 0);
		up_write(&current->mm->mmap_sem);
	}
	h_pers = (lc_handler_t)current_thread_info()->exec_domain->handler;
	(h_pers)(segment,regs);
	return;
}

static void
init_perlist(void)
{
	int		i;
	char		*p, *s;
	unsigned long	l;
	mm_segment_t	fs;

	abi_perlist = (char *)0;
	if (!ExeFlags) return;

	fs=get_fs(); set_fs(get_ds());
	i = SYS_NATIVE(open,ExeFlags,0,0);
	if (i >= 0) {
		abi_perlist = (char *)kmalloc(PAGE_SIZE,GFP_KERNEL);
		if (abi_perlist) {
			abi_perlist[1] = '<';
			SYS_NATIVE(read,i,abi_perlist+1,PAGE_SIZE-1);
		}
		SYS_NATIVE(close,i);
	}
	set_fs(fs);

	if (!abi_perlist) return;
	p = abi_perlist; 
	p[PAGE_SIZE-2] = '\n'; p[PAGE_SIZE-1] = '<';

	while(p[1] != '<') {
		s = p+1;
		while (s[0] != '\n') s++;
		p[0] = s-p;
		p  = s; p[0] = '\0';
		s -= 9; s[0] = '\0';
		l  = 0;
		while (1) {
		  s++; i = s[0];
		  if ( i <= '9' && i>= '0' ) { l = l*16 + i - 48; continue; }
		  if ( i <= 'F' && i>= 'A' ) { l = l*16 + i - 55; continue; }
		  if ( i <= 'f' && i>= 'a' ) { l = l*16 + i - 87; continue; }
		  break;
		}
		*((unsigned long *)(p-sizeof(long))) = l;
	}
	return;
}

static struct exec_domain linux_exec_domain = {
	name:		"Lcall7_detection",
	handler:	(handler_t)linux_lcall7,
	pers_low:	99,
	pers_high:	99,
	module:		THIS_MODULE
};
static struct exec_domain *pLinuxExec;
static handler_t old_lcall7;
static int lcall_init_done = 0;

#ifdef	CONFIG_64BIT
static u64 old_idt_entry[2] = {0, 0};

typedef struct { u16 limit; u64* ptr; } __attribute__((packed)) descr_t;

static void
lcall_idt_init(void) {
	descr_t idt_descr;
	extern void lcall_int(void);

	asm volatile("sidt %0":"=m" (idt_descr));
	old_idt_entry[0] = idt_descr.ptr[Amd64vector*2+0];
	old_idt_entry[1] = idt_descr.ptr[Amd64vector*2+1];
	idt_descr.ptr[Amd64vector*2+0] = 
		((u64)lcall_int & 0xFFFF)		<< 0  | 
		__KERNEL_CS	 	 		<< 16 |
		(u64)0xee00L				<< 32 |
		((u64)lcall_int >> 16 & 0xFFFF)	<< 48;
	idt_descr.ptr[Amd64vector*2+1] = (u64)lcall_int >> 32;
	asm volatile("lidt %0":"=m" (idt_descr));
}

static void lcall_idt_restore(void) {
	descr_t idt_descr;

	if (old_idt_entry[0]) {
	      asm volatile("sidt %0":"=m" (idt_descr));
	      idt_descr.ptr[Amd64vector*2+0] = old_idt_entry[0];
	      idt_descr.ptr[Amd64vector*2+1] = old_idt_entry[1];
	      asm volatile("lidt %0":"=m" (idt_descr));
	}
}
#endif

static int
lcall_load_binary(struct linux_binprm *bpp, struct pt_regs *rp)
{
	unsigned long lPers, entry32, entry64 = 0;

	if (!lcall_init_done) {
		lPers = (*((long *)(bpp->buf+36))) & 0xFFFFFFFF;
		if (lPers != ELF_X286) return -ENOEXEC;
		if (_DX(rp) != 0) return -ENOEXEC;
#ifdef CONFIG_64BIT
		rdmsrl(MSR_LSTAR,entry64);
#endif
		entry32 = ((unsigned long *)rp)[-1];
		if ( lcall_syscall_init(entry64,entry32) != 0 ) return -ENOEXEC;
		init_perlist();
		lcall_init_done = 1;
		return -ENOEXEC;
	}

#ifdef CONFIG_ABI_ELFMARK
	lPers = (*((long *)(bpp->buf+36))) & 0xFFFFFFFF;
	if (lPers == ELF_SVR4 || lPers == ELF_OSR5 ||
	    lPers == ELF_UXW7 || lPers == ELF_X286 )
#endif
		lcall_ldt_on_syscall_return(rp);
	return -ENOEXEC;
}

#if _KSL > 23
static struct linux_binfmt lcall_format = {
	{NULL, NULL}, THIS_MODULE, lcall_load_binary, NULL, NULL, PAGE_SIZE, 0
};
#else
static struct linux_binfmt lcall_format = {
	NULL, THIS_MODULE, lcall_load_binary, NULL, NULL, PAGE_SIZE
};
#endif

static int __init
lcall_init(void)
{
	int err;

	/*
	 * No value for Amd64vector is guarrenteed to be safe, put putting
	 * in the trap, hardware, SYSCALL, or APIC range is asking for
	 * trouble.
	 */
	if (Amd64vector < 96 || Amd64vector == 128 || Amd64vector >= 224) {
	    printk(KERN_ERR
		    "abi_lcall: Amd64vector parameter (=%d) is invalid\n",
		    Amd64vector);
	    return -EINVAL;
	}
	err = register_exec_domain(&linux_exec_domain);
	if (err != 0) return err;
	for (pLinuxExec = &linux_exec_domain; pLinuxExec; pLinuxExec=pLinuxExec->next)
		if (pLinuxExec->pers_low==0) break;
	unregister_exec_domain(&linux_exec_domain);
	if (!pLinuxExec) return -1;
	old_lcall7 = pLinuxExec->handler;
	pLinuxExec->handler = (handler_t)linux_lcall7;

#if _KSL > 29
	err = insert_binfmt(&lcall_format);
#else
	err = register_binfmt(&lcall_format);
#endif
	if (err < 0)
		return err;
#ifdef	CONFIG_64BIT
	lcall_idt_init();
#endif
	return err;
}

static void __exit
lcall_exit(void)
{
	unregister_binfmt(&lcall_format);
	if (abi_perlist) kfree(abi_perlist);
	pLinuxExec->handler = old_lcall7;
#ifdef	CONFIG_64BIT
	lcall_idt_restore();
#endif
}

#if	0
#ifdef CONFIG_XEN
static void write_xen(void* lp, u64 val) {
	xmaddr_t mach_lp = arbitrary_virt_to_machine(lp);
	HYPERVISOR_update_descriptor((u64)mach_lp.maddr, val);
}
#endif
#endif

static void
write_ldt_call_gate(u64* ldt, int n, void* addr, u16 cs) {
#ifdef	CONFIG_64BIT
	u64 lldt[2];

	lldt[1] = (u64)addr >> 32;
#else
	u64 lldt[1];
#endif
	lldt[0] =
	  	((long)addr & 0xFFFF) 			<< 0  |
	  	cs 					<< 16 |
		0xec00LL				<< 32 |
		(((u64)(long)addr >> 16) & 0xFFFF)	<< 48;

	/*
	 * 2.6.32 doesn't export the symbol arbitrary_virt_to_machine(), so
	 * the XEN interface below doesn't work on an unpatched kernel.
	 */
#if	0
#ifdef CONFIG_XEN
	if (xen_domain()) {
		__u32 *lp = 
		xmaddr_t mach_lp = arbitrary_virt_to_machine(lp);
#ifdef	CONFIG_64BIT
		write_xen((char *)ldt + (n + 1) * 8, lldt[1]);
#endif
		write_xen((char *)ldt + (n + 0) * 8, lldt[0]);
		return;

	}
#endif
#endif

	memcpy(&ldt[n], lldt, sizeof(lldt));
}

/*
 * Insert the appropriate gates into the LDT, so the lcall's done by the
 * iBCS program work.
 */
void
lcall_ldt()
{
	mm_segment_t fs;
	u64 *ldt;
	u16 cs;
	void* gate7;
        void* gate27;
	struct user_desc l_e;

	fs=get_fs();

	memset(&l_e,0,sizeof(l_e));
	l_e.entry_number = 7;	/* make sure we can fit lcall 0x7 and 0x27 */
				/* force LDT allocation */
	set_fs(get_ds());
	SYS_NATIVE(modify_ldt,1,&l_e,sizeof(l_e));
	set_fs(fs);

#ifdef MAX_LDT_PAGES
	ldt = (u64 *)kmap(current->mm->context.ldt_pages[0]);
#else
	ldt = (u64 *)current->mm->context.ldt;
#endif
	if(!ldt) return;

#ifdef	CONFIG_64BIT
	/*
	 * Problem: direct lcall's into ring 0 don't work in 64 bit mode.
	 * In 64 bit mode the swapgs instruction is used to flip between
	 * user mode and right per_cpu address space.  On entry via an
	 * interrupt or syscall the kernel figures out whether it has to do
	 * a swapgs by looking at the ring (low order bits of CS).  The kernel
	 * lives in ring 0, so if the ring was 0 the interrupt happened while
	 * the kernel was running, so another swapgs must not be done.  There
	 * is a race here: if there are nested interrupts, and the second one
	 * happens before the first one has had a chance to execute swapgs
	 * disaster would ensue.  Fortunately, interrupts and syscall's switch
	 * interrupts off so the race can be avoided.  Sadly, lcall's don't
	 * disable interrupts so the race becomes real.
	 *
	 * There aren't too many options here.  lcall's can't be allowed to
	 * go to ring 0, so they jump to a valid address in user space.
	 * Naturally at that address must be code that takes us into the
	 * kernel, and of course that code doesn't exist so we have to create
	 * it.  Worse, amd64 doesn't allow lcall's to 32 bit code segments, so
	 * it must be in a different code segment.  There are only two ways to
	 * enter the kernel with interrupts off: software interrupt or
	 * sysenter.  Sysenter is taken, so we use the (hopefully available)
	 * int $0x81.
	 */
	{
	  	descr_t gdt_descr;
		u64 addr;
		struct vm_area_struct *vma;
		struct {
		  u8 pushq_1;
		  u8 imm_1;
		  u8 int_1;
		  u8 irq_1;
		  u8 pushq_2;
		  u8 imm_2;
		  u8 int_2;
		  u8 irq_2;
		} __attribute__((packed)) code = {
		  0x6a, 7,		/* lcall_gate7: pushq $7 */
		  0xcd, Amd64vector, 	/* int Amd64vector */
		  0x6a, 27,		/* lcall_gate27: pushq $27 */
		  0xcd, Amd64vector, 	/* int Amd64vector */
		};

		down_write(&current->mm->mmap_sem);
		addr = do_mmap(
		    NULL, 0L, PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE,
		    MAP_PRIVATE | MAP_EXECUTABLE | MAP_32BIT, 0);
		up_write(&current->mm->mmap_sem);
		vma = find_vma(current->mm, addr);
		if (!vma || !(pgprot_val(vma->vm_page_prot) & _PAGE_USER))
		  	return;
		if (copy_to_user((char *)addr,&code,sizeof(code)))
			return;
		cs = 23;
		gate7 = (void*)addr;
		gate27 = (void*)(addr + 4);
		asm volatile("sgdt %0":"=m" (gdt_descr));
		ldt[cs >> 3] =		/* Alias __USER32_CS, but 64 bit */
			(gdt_descr.ptr[__USER32_CS / 8] & ~(0x3L << 53)) |
			0x1L << 53;
	}
#else
	{
	  	extern void lcall_gate7(void);
	  	extern void lcall_gate27(void);
		cs = __KERNEL_CS;
		gate7 = lcall_gate7;
		gate27 = lcall_gate27;
	}
#endif

	write_ldt_call_gate(ldt, 0, gate7, cs);
	write_ldt_call_gate(ldt, 4, gate27, cs);

	set_fs(get_ds());	/* Force LDT reload */
	SYS_NATIVE(modify_ldt,1,&l_e,sizeof(l_e));
	set_fs(fs);
}

module_init(lcall_init);
module_exit(lcall_exit);

EXPORT_SYMBOL(lcall7_syscall);
EXPORT_SYMBOL(lcall7_dispatch);
EXPORT_SYMBOL(lcall_syscall);
#ifdef	CONFIG_64BIT
EXPORT_SYMBOL(lcall_syscall64);
#endif
EXPORT_SYMBOL(abi_personality);
EXPORT_SYMBOL(lcall_ldt);
