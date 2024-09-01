# Andrea Efficace <andrea.efficace1@gmail.com>
# July 29, 2024
# Makefile for a kernel-level Reference Monitor for File Protection.
# This module depends on the "SCTH" module.


# Module Name
MODNAME=kremfip
# Submodule Name
SCTHNAME=scth
# Module Version
VERSION=0.1

# Compiler
CC=gcc

# Current Directory
PWD := $(shell pwd)

# Kernel Module Directory
KDIR = /lib/modules/$(shell uname -r)/build
# Syscall table hacking module directory
SCTHDIR = $(PWD)/scth

# Kernel Module Source Files
INCLUDE = include/rmfs.o include/misc.o include/ht_dllist.o
UTILS = utils/murmurhash3.o utils/rm_syscalls.o

# Compiler Flags
CFLAGS = -Wall -Wextra -Werror -Wno-implicit-fallthrough -Wno-unused-function -O2 -g

# make command invoked from the command line.
ifeq ($(KERNELRELEASE),)
.PHONY: all install clean uninstall load unload

all:
	cd $(SCTHDIR) && $(MAKE) all
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"

clean:
	cd $(SCTHDIR) && $(MAKE) clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	cd $(SCTHDIR) && $(MAKE) install
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
	ln -s /lib/modules/$(shell uname -r)/extra/$(MODNAME).ko /lib/modules/$(shell uname -r)
	depmod -a

uninstall:
	rm /lib/modules/$(shell uname -r)/extra/$(MODNAME).ko
	rm /lib/modules/$(shell uname -r)/$(MODNAME).ko
	depmod -a

load:
	echo "$(MODNAME) Loading..."
	cd $(SCTHDIR) && $(MAKE) load
	sudo insmod $(MODNAME).ko

unload:
	echo "$(MODNAME) Removing..."
	cd $(SCTHDIR) && $(MAKE) unload
	sudo rmmod $(MODNAME).ko
else
# make command invoked from the kernel build system.
obj-m += $(MODNAME).o
$(MODNAME)-y := kremfip_main.o $(INCLUDE) $(UTILS)
KBUILD_EXTRA_SYMBOLS = $(SCTHDIR)/Module.symvers
ifeq ($(DEBUG), 1)
ccflags-y += -DDEBUG
endif
endif
