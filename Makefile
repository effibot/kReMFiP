# Andrea Efficace <andrea.efficace1@gmail.com>
# July 29, 2024
# Makefile for a kernel-level Reference Monitor for File Protection.
# This module depends on the "SCTH" module.


# Module Name
MODNAME := kremfip
# Module Version
VERSION := 0.1
# Kernel Module Directory
KDIR ?= /lib/modules/$(shell uname -r)/build
# Current Directory
PWD := $(shell pwd)
# Source Directory
SRCDIR := src
# Sub-module Directory
SCTHDIR := scth
# Include Directory
INCLUDEDIR := $(SRCDIR)/include
# Utilities Directory
UTILSDIR := $(SRCDIR)/utils
# Library Directory
LIBDIR := $(SRCDIR)/lib
# Test Directory
TESTDIR := $(PWD)/test
# User Directory
USERDIR := $(PWD)/user


# Source files
SRC := $(SRCDIR)/kremfip_main.o
# Core Headers
INCLUDE := $(INCLUDEDIR)/rm.o $(INCLUDEDIR)/syscalls.o
# Utils stuffs
UTILS := $(UTILSDIR)/misc.o $(UTILSDIR)/pathmgm.o
# Library stuffs
LIBS := $(LIBDIR)/hash/murmurhash3.o $(LIBDIR)/ht_dll_rcu/ht_dllist.o

# Compiler Flags
CFLAGS := -Wno-declaration-after-statement -Wno-implicit-fallthrough -Wno-unused-function -O3 -g

# make command invoked from the command line.
ifeq ($(KERNELRELEASE),)
.PHONY: all clean load unload user

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"

clean:
	@cd $(SCTHDIR) && $(MAKE) clean
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@if [ -f $(USERDIR)/user_test ]; then rm $(USERDIR)/user_test; fi

load:
	@echo "$(MODNAME) Loading..."
	cd $(SCTHDIR) && $(MAKE) load
	sudo insmod $(MODNAME).ko

unload:
	@echo "$(MODNAME) Removing..."
	cd $(SCTHDIR) && $(MAKE) unload
	sudo rmmod $(MODNAME).ko
user:
	@cd $(USERDIR) && $(MAKE) all
else
# make command invoked from the kernel build system.
obj-m += $(MODNAME).o
obj-y += $(SCTHDIR)/
$(MODNAME)-y += $(SRC) $(INCLUDE) $(UTILS) $(LIBS)
KBUILD_EXTRA_SYMBOLS += $(SCTHDIR)/Module.symvers
ifeq ($(DEBUG), 1)
ccflags-y += -DDEBUG
endif
endif
