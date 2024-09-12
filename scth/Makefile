# Date: 31/08/2024
# Author: Andrea Efficace <andrea.efficace1@gmail.com>
# Makefile for the "System Call Table Hacker" kernel module.
# NOTE: To activate debugging in this module, set DEBUG=1 from the command line.

MODNAME:=scth
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
SRCDIR := src
TESTDIR := ./test
INCLUDEDIR := $(SRCDIR)/include
UTILSDIR := $(SRCDIR)/utils
VERSION := 1.0

# Compiler Flags
CFLAGS := -Wno-declaration-after-statement -O3 -g
# Source files
SRC := $(SRCDIR)/scth_main.o
# Core Headers
INCLUDE := $(INCLUDEDIR)/scth_lib.o
# Utils stuffs
UTILS := $(UTILSDIR)/paging_navigator.o
# Test stuffs
TESTS := $(TESTDIR)/tests.o
ifeq ($(KERNELRELEASE),)
.PHONY: all  clean load unload test
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod $(MODNAME).ko
unload:
	sudo rmmod $(MODNAME).ko
test:
# compile the module if not already done
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"
# load the module
	sudo insmod $(MODNAME).ko
# compile the test module and run the tests
	cd $(TESTDIR) && $(MAKE) test
# unload the module
	sudo rmmod $(MODNAME).ko

else
# directives
obj-m += $(MODNAME).o
$(MODNAME)-objs += $(SRC) $(INCLUDE) $(UTILS)
ifeq ($(DEBUG), 1)
ccflags-y += -DDEBUG
endif
ifeq ($(SHOW_NUMBERS), 1)
ccflags-y += -DSHOW_NUMBERS
endif
endif

