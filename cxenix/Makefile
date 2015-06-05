abi_cxenix-objs	:= sysent.o misc.o stubs.o signal.o pathconf.o utsname.o

obj-m	+= abi_cxenix.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_misc.o = -O2 -Os
CFLAGS_REMOVE_pathconf.o = -O2 -Os
CFLAGS_REMOVE_signal.o = -O2 -Os
CFLAGS_REMOVE_stubs.o = -O2 -Os
CFLAGS_REMOVE_sysent.o = -O2 -Os
CFLAGS_REMOVE_utsname.o = -O2 -Os
endif
