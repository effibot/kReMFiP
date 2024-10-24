# Andrea Efficace <andrea.efficace1@gmail.com>
# July 29, 2024
# Makefile for a kernel-level Reference Monitor for File Protection.
# This module depends on the "SCTH" module.


# Module Name
MODNAME := kremfip
# Module Version
VERSION := 1.0
# Kernel Module Directory
KDIR ?= /lib/modules/$(shell uname -r)/build
# Source Directory
SRCDIR := src
# Sub-module Directory
SCTHDIR := scth
LOGFSDIR := loggerfs
# Include Directory
INCLUDEDIR := $(SRCDIR)/include
# Utilities Directory
UTILSDIR := $(SRCDIR)/utils
# Library Directory
LIBDIR := $(SRCDIR)/lib
# Test Directory
TESTDIR := test
# User Directory
USERDIR := user

# Source files
SRC := $(SRCDIR)/kremfip_main.o
# Core Headers
INCLUDE := $(INCLUDEDIR)/rm.o $(INCLUDEDIR)/syscalls.o
# Utils stuffs
UTILS := $(UTILSDIR)/misc.o $(UTILSDIR)/pathmgm.o
# Library stuffs
LIBS := $(LIBDIR)/hash/murmurhash3.o $(LIBDIR)/ht_dll_rcu/ht_dllist.o

# Compiler Flags
CFLAGS := -std=gnu11 -Wno-comment -Wno-declaration-after-statement -Wno-implicit-fallthrough -Wno-unused-function -O3 -g

# Module configuration
obj-m += $(MODNAME).o
obj-y += $(SCTHDIR)/ $(LOGFSDIR)/
$(MODNAME)-y += $(SRC) $(INCLUDE) $(UTILS) $(LIBS)
KBUILD_EXTRA_SYMBOLS += $(PWD)/$(SCTHDIR)/Module.symvers

ifeq ($(DEBUG), 1)
CFLAGS += -DDEBUG
endif

# Targets
.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)" -j
	$(MAKE) -C $(LOGFSDIR) app
	$(MAKE) -C $(USERDIR) cli

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(LOGFSDIR) remove
	$(MAKE) -C $(USERDIR) clean
