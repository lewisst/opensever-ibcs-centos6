abi_sco-objs	:= sysent.o misc.o mmap.o ptrace.o secureware.o \
		   stat.o statvfs.o ioctl.o termios.o tapeio.o vtkbd.o

obj-m	+= abi_sco.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_ioctl.o = -O2 -Os
CFLAGS_REMOVE_misc.o = -O2 -Os
CFLAGS_REMOVE_mmap.o = -O2 -Os
CFLAGS_REMOVE_ptrace.o = -O2 -Os
CFLAGS_REMOVE_secureware.o = -O2 -Os
CFLAGS_REMOVE_stat.o = -O2 -Os
CFLAGS_REMOVE_statvfs.o = -O2 -Os
CFLAGS_REMOVE_sysent.o = -O2 -Os
CFLAGS_REMOVE_tapeio.o = -O2 -Os
CFLAGS_REMOVE_termios.o = -O2 -Os
CFLAGS_REMOVE_termios.o = -O2 -Os
CFLAGS_REMOVE_vtkbd.o = -O2 -Os
endif
