# Date: 31/08/2024
# Author: Andrea Efficace <andrea.efficace1@gmail.com>
# Makefile for the "System Call Table Hacker" kernel module.
# NOTE: To activate debugging in this module, set DEBUG=1 from the command line.

MODNAME=scth


ifeq ($(KERNELRELEASE),)
.PHONY: all install clean uninstall load unload
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
install:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
	ln -s /lib/modules/$(shell uname -r)/extra/$(MODNAME).ko /lib/modules/$(shell uname -r)
uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/$(MODNAME).ko
	rm -f /lib/modules/$(shell uname -r)/$(MODNAME).ko
	depmod -a
load:
	sudo insmod $(MODNAME).ko
unload:
	sudo rmmod $(MODNAME).ko
else
obj-m += $(MODNAME).o
$(MODNAME)-y := scth_main.o scth_lib.o utils/paging_navigator.o
ifeq ($(DEBUG), 1)
ccflags-y += -DDEBUG
endif
endif
