abi_isc-objs	:= sysent.o

obj-m	+= abi_isc.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_sysent.o = -O2 -Os
endif
