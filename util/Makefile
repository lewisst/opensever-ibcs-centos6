ifdef ABI_DIR
  include $(ABI_DIR)/CONFIG
  include $(ABI_DIR)/SETFLG
endif

ifeq ($(ABI_NOOPT),Y)
CFLAGS_REMOVE_plist.o = -Os -O2
CFLAGS_REMOVE_proc.o = -Os -O2
CFLAGS_REMOVE_shinomap.o = -Os -O2
CFLAGS_REMOVE_stat.o = -Os -O2
endif


abi_util-objs	:= stat.o plist.o

ifeq ($(ABI_PROC),Y)
abi_util-objs	+= proc.o
endif

ifeq ($(ABI_SHINOMAP),Y)
abi_util-objs	+= shinomap.o
endif

obj-m	+= abi_util.o

#---------------------------------------
all: elf_mark abitrace abi_exec

abitrace: abitrace.o
	$(LD) -m elf_i386 -s -o $@ $<
	./elf_mark -4 abitrace
abitrace.o: abitrace.S
	$(CC) -m32 -c $<

elf_mark: elf_mark.o
	$(LD) -m elf_i386 -s -o $@ $<
elf_mark.o: elf_mark.S
	$(CC) -m32 -c $<

abi_exec: abi_exec.o
	$(LD) -m elf_i386 -s -o $@ $<
	./elf_mark -2 abi_exec
abi_exec.o: abi_exec.S
	$(CC) -m32 -c $<

