binfmt_xout-objs	:= binfmt-xout.o

obj-m	+= binfmt_xout.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_binfmt-xout.o = -O2 -Os
endif
