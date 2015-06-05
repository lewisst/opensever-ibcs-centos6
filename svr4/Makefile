abi_svr4-objs	:= hrtsys.o ioctl.o ipc.o mmap.o open.o svr4.o sysconf.o \
		   sysfs.o sysinfo.o sysi86.o ulimit.o utsname.o stream.o \
		   stat.o socksys.o signal.o misc.o socket.o statvfs.o \
		   fcntl.o filio.o termios.o consio.o tapeio.o sockio.o \
		   timod.o xti.o

obj-m	+= abi_svr4.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_consio.o = -Os -O2
CFLAGS_REMOVE_fcntl.o = -Os -O2
CFLAGS_REMOVE_filio.o = -Os -O2
CFLAGS_REMOVE_hrtsys.o = -Os -O2
CFLAGS_REMOVE_ioctl.o = -Os -O2
CFLAGS_REMOVE_ipc.o = -Os -O2
CFLAGS_REMOVE_misc.o = -Os -O2
CFLAGS_REMOVE_mmap.o = -Os -O2
CFLAGS_REMOVE_open.o = -Os -O2
CFLAGS_REMOVE_signal.o = -Os -O2
CFLAGS_REMOVE_socket.o = -Os -O2
CFLAGS_REMOVE_sockio.o = -Os -O2
CFLAGS_REMOVE_socksys.o = -Os -O2
CFLAGS_REMOVE_stat.o = -Os -O2
CFLAGS_REMOVE_statvfs.o = -Os -O2
CFLAGS_REMOVE_stream.o = -Os -O2
CFLAGS_REMOVE_svr4.o = -Os -O2
CFLAGS_REMOVE_sysconf.o = -Os -O2
CFLAGS_REMOVE_sysfs.o = -Os -O2
CFLAGS_REMOVE_sysi86.o = -Os -O2
CFLAGS_REMOVE_sysinfo.o = -Os -O2
CFLAGS_REMOVE_tapeio.o = -Os -O2
CFLAGS_REMOVE_termios.o = -Os -O2
CFLAGS_REMOVE_timod.o = -Os -O2
CFLAGS_REMOVE_ulimit.o = -Os -O2
CFLAGS_REMOVE_utsname.o = -Os -O2
CFLAGS_REMOVE_xti.o = -Os -O2
endif
