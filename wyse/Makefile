abi_wyse-objs	:= sysent.o ptrace.o socket.o

obj-m	+= abi_wyse.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_ptrace.o = -O2 -Os
CFLAGS_REMOVE_socket.o = -O2 -Os
CFLAGS_REMOVE_sysent.o = -O2 -Os
endif
