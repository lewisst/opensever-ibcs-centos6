abi_solaris-objs:= lfs.o solarisx86.o socket.o stat.o sysent.o

obj-m	+= abi_solaris.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_lfs.o = -O2 -Os
CFLAGS_REMOVE_socket.o = -O2 -Os
CFLAGS_REMOVE_solarisx86.o = -O2 -Os
CFLAGS_REMOVE_stat.o = -O2 -Os
CFLAGS_REMOVE_sysent.o = -O2 -Os
endif
