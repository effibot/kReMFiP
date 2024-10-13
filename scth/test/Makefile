# Date: 31/08/2024
# Author: Andrea Efficace <andrea.efficace1@gmail.com>
# Makefile for the "System Call Table Hacker" kernel module.
# NOTE: To activate debugging in this module, set DEBUG=1 from the command line.

MODNAME:=scth_test
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
VERSION := 1.0

# Compiler Flags
CFLAGS := -Wno-declaration-after-statement -O3 -g -std=gnu11
# Source files
SRC := sys_hack.o
ifeq ($(KERNELRELEASE),)
.PHONY: test clean all
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
test:
# compile the test module
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"
# load the test module
	sudo insmod $(MODNAME).ko
# run the test
	gcc -o test test.c
	./test
# unload the test module
	sudo rmmod $(MODNAME).ko
# clean the test module
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f test

else
# directives
obj-m += $(MODNAME).o
obj-y += ../
$(MODNAME)-y += $(SRC)
KBUILD_EXTRA_SYMBOLS := ../Module.symvers
endif
