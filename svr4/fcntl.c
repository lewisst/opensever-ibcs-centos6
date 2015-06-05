/*
 * Copyright (c) 2002 Caldera Deutschland GmbH.
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

#include "../include/util/i386_std.h"
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>
#ifdef CONFIG_64BIT
#include <asm/compat.h>
#endif

#include "../include/svr4/types.h"
#include "../include/util/trace.h"
#include "../include/util/map.h"


struct svr4_flock {
	int16_t	    l_type;	/* numbers don't match */
	int16_t	    l_whence;
	svr4_off_t  l_start;
	svr4_off_t  l_len;	/* 0 means to end of file */
	int16_t	    l_sysid;
	int16_t	    l_pid;
};


/*
 * ISC (at least) assumes O_CREAT if O_TRUNC is given.
 * This is emulated here but is it correct for SVR4 in general?
 */
unsigned short fl_svr4_to_linux[] = {
	0x0001, 0x0002, 0x0800, 0x0400, 0x1000, 0x0000, 0x0000, 0x0800,
	0x0040, 0x0240, 0x0080, 0x0100, 0x0000, 0x0000, 0x0000, 0x0000
};

unsigned short fl_linux_to_svr4[] = {
	0x0001, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x0100, 0x0400,
	0x0800, 0x0200, 0x0008, 0x0004, 0x0010, 0x0000, 0x0000, 0x0000
};

static inline int svr4_fcntl_flock(int fd, unsigned int cmd, unsigned long arg)
{
	struct svr4_flock fl, *flp = (struct svr4_flock *)arg;

#ifdef CONFIG_64BIT
	struct compat_flock l_fl;
#else
	struct flock l_fl;
#endif
	int rval;

	/*
	 * We are not supposed to fail once the lock is set,
	 * thus we check the userspace pointer for writeaccess now.
	 */
	if (!access_ok(VERIFY_WRITE, flp, sizeof(struct svr4_flock)))
		return -EFAULT;

	rval = copy_from_user(&fl, flp, sizeof(struct svr4_flock));
	if (rval)
		return -EFAULT;

	l_fl.l_type = fl.l_type - 1;
	l_fl.l_whence = fl.l_whence;
	l_fl.l_start = fl.l_start;
	l_fl.l_len = fl.l_len;
	l_fl.l_pid = fl.l_pid;

#if defined(CONFIG_ABI_TRACE)
	abi_trace(ABI_TRACE_API,
		"lock l_type: %d l_whence: %d "
		"l_start: %u l_len: %u "
		"l_sysid: %d l_pid: %d\n",
		fl.l_type, fl.l_whence,
		fl.l_start, fl.l_len,
		fl.l_sysid, fl.l_pid);
#endif
	copy_to_user(flp, &l_fl, sizeof(struct svr4_flock));

	rval = SYS(fcntl,fd, cmd, flp);

	if (rval) {
		copy_to_user(flp, &fl, sizeof(struct svr4_flock));
		return rval;
	}
	copy_from_user(&l_fl, flp, sizeof(struct svr4_flock));

	fl.l_type = l_fl.l_type + 1;
	fl.l_whence = l_fl.l_whence;
	fl.l_start = l_fl.l_start;
	fl.l_len = l_fl.l_len;
	fl.l_sysid = 0;
	fl.l_pid = l_fl.l_pid;

	if (__copy_to_user(flp, &fl, sizeof(struct svr4_flock)))
		return -EFAULT;
	return 0;
}

int svr4_fcntl(int fd, unsigned int cmd, unsigned long arg)
{
	int rval;

	switch (cmd) {
	case 0: /* F_DUPFD */
	case 1: /* F_GETFD */
	case 2: /* F_SETFD */
		rval = SYS(fcntl,fd, cmd, arg); return rval;
	case 3: /* F_GETFL */
		rval = SYS(fcntl,fd, cmd, arg);
		return map_flags(rval, fl_linux_to_svr4);
	case 4: /* F_SETFL */
		arg = map_flags(arg, fl_svr4_to_linux);
		rval = SYS(fcntl,fd, cmd, arg); return rval;
	case 14: /* F_GETLK SVR4 */
		cmd = 5;
		/*FALLTHROUGH*/
	case 5: /* F_GETLK */
	case 6: /* F_SETLK */
	case 7: /* F_SETLKW */
		return svr4_fcntl_flock(fd, cmd, arg);
	case 10: /* F_ALLOCSP */
		/* Extend allocation for specified portion of file. */
		return 0;
	case 11: /* F_FREESP */
		/* Free a portion of a file. */
		return 0;

	/*
	 * These are intended to support the Xenix chsize() and
	 * rdchk() system calls. I don't know if these may be
	 * generated by applications or not.
	 */
	case 0x6000: /* F_CHSIZE */
		rval = SYS(ftruncate,fd, arg); return rval;
	case 0x6001: /* F_RDCHK */
	    {
		mm_segment_t fs;
		int nbytes;

		fs = get_fs();
		set_fs(get_ds());
		rval = SYS_NATIVE(ioctl,fd, FIONREAD, (long)&nbytes);
		set_fs(fs);

		if (rval < 0)
			return rval;
		return (nbytes ? 1 : 0);
	    }

	case  8: /* F_CHKFL */
	    /*FALLTHROUGH*/

	/*
	 * These are made from the Xenix locking() system call.
	 * According to available documentation these would
	 * never be generated by an application - only by the
	 * kernel Xenix support.
	 */
	case 0x6300: /* F_LK_UNLCK */
	case 0x7200: /* F_LK_LOCK */
	case 0x6200: /* F_LK_NBLCK */
	case 0x7100: /* F_LK_RLCK */
	case 0x6100: /* F_LK_NBRLCK */
	    /*FALLTHROUGH*/

	default:
#if defined(CONFIG_ABI_TRACE)
		abi_trace(ABI_TRACE_API,
			"unsupported fcntl 0x%x, arg 0x%lx\n", cmd, arg);
#endif
		return -EINVAL;
	}
}

EXPORT_SYMBOL(fl_svr4_to_linux);
EXPORT_SYMBOL(svr4_fcntl);
