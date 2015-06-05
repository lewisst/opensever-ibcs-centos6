abi_uw7-objs	:= access.o context.o ioctl.o lfs.o mac.o \
		   misc.o mmap.o stat.o sysent.o

obj-m	+= abi_uw7.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_access.o = -O2 -Os
CFLAGS_REMOVE_context.o = -O2 -Os
CFLAGS_REMOVE_ioctl.o = -O2 -Os
CFLAGS_REMOVE_lfs.o = -O2 -Os
CFLAGS_REMOVE_mac.o = -O2 -Os
CFLAGS_REMOVE_misc.o = -O2 -Os
CFLAGS_REMOVE_mmap.o = -O2 -Os
CFLAGS_REMOVE_stat.o = -O2 -Os
CFLAGS_REMOVE_sysent.o = -O2 -Os
endif
