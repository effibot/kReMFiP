# Date: 31/08/2024
# Author: Andrea Efficace <andrea.efficace1@gmail.com>
# Makefile for the "System Call Table Hacker" kernel module.
# NOTE: To activate debugging in this module, set DEBUG=1 from the command line.

MODNAME := scth
KDIR ?= /lib/modules/$(shell uname -r)/build
SRCDIR := src
TESTDIR := test
INCLUDEDIR := $(SRCDIR)/include
UTILSDIR := $(SRCDIR)/utils

# Compiler Flags
CFLAGS := -std=gnu11 -Wno-comment -Wno-declaration-after-statement -Wno-implicit-fallthrough -Wno-unused-function -O3 -g
# Source files
SRC := $(SRCDIR)/scth_main.o
# Core Headers
INCLUDE := $(INCLUDEDIR)/scth_lib.o
# Utils stuffs
UTILS := $(UTILSDIR)/paging_navigator.o
# Test stuffs
TESTS := $(TESTDIR)/tests.o

# directives
obj-m += $(MODNAME).o
$(MODNAME)-y += $(SRC) $(INCLUDE) $(UTILS)

.PHONY: all  clean load unload test
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers
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
