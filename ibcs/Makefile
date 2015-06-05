abi_ibcs-objs	:= sysent.o

obj-m	+= abi_ibcs.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_sysent.o = -Os -O2
endif
