binfmt_coff-objs	:= binfmt-coff.o

obj-m	+= binfmt_coff.o

include $(ABI_DIR)/SETFLG

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_binfmt-coff.o = -Os -O2
endif
