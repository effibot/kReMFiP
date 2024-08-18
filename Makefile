# Andrea Efficace <andrea.efficace1@gmail.com>
# July 29, 2024
# Makefile for a kernel-level Reference Monitor for File Protection.
# This module depends on the "SCTH" module.


# Module Name
MODNAME=kremfip

# Module Version
VERSION=0.1

# Compiler
CC=gcc


# Current Directory
PWD := $(shell pwd)

# External libraries to link
IDIR=$(PWD)/../include
INCLUDES=-I$(IDIR)

# Kernel Module Directory
KDIR := /lib/modules/$(shell uname -r)/build


# Compiler Flags
CFLAGS=-Wall -Wextra -Werror $(INCLUDES)
LDFLAGS=-L$(PWD)/../include

# make command invoked from the command line.
ifeq ($(KERNELRELEASE),)
.PHONY: all install clean uninstall load unload

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
	ln -s /lib/modules/$(shell uname -r)/extra/$(MODNAME).ko /lib/modules/$(shell uname -r)
	depmod -a

uninstall:
	rm /lib/modules/$(shell uname -r)/extra/$(MODNAME).ko
	rm /lib/modules/$(shell uname -r)/$(MODNAME).ko
	depmod -a

load:
	echo "$(MODNAME) Loading..."
	sudo insmod $(MODNAME).ko

unload:
	echo "$(MODNAME) Removing..."
	sudo rmmod $(MODNAME).ko
else
# make command invoked from the kernel build system.
obj-m += $(MODNAME).o
$(MODNAME)-y := kremfip_main.o include/rmfs.o include/utils.o include/ht_dllist.o
ifeq ($(DEBUG), 1)
ccflags-y += -DDEBUG
endif
endif
