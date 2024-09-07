# Date: 31/08/2024
# Author: Andrea Efficace <andrea.efficace1@gmail.com>
# Makefile for the "System Call Table Hacker" kernel module.
# NOTE: To activate debugging in this module, set DEBUG=1 from the command line.

MODNAME=scth
CFLAGS =  -Wno-declaration-after-statement -O3 -g #-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-value -Wno-unused-label -Wno-unused-const-variable -Wno-unused-const-variable -Wno-unused-label -Wno-unused-value -Wno-unused-but-set-variable -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable

ifeq ($(KERNELRELEASE),)
.PHONY: all  clean load unload
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)"

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod $(MODNAME).ko
unload:
	sudo rmmod $(MODNAME).ko
else
obj-m += $(MODNAME).o
$(MODNAME)-y := scth_main.o lib/scth_lib.o utils/paging_navigator.o
ifeq ($(DEBUG), 1)
ccflags-y += -DDEBUG
endif
endif
