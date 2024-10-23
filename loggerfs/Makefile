# Module Name
MODNAME := loggerfs
# Module Version
VERSION := 1.0
# Kernel Module Directory
KDIR ?= /lib/modules/$(shell uname -r)/build
# Source Directory
SRCDIR := src
# Source Files
SRC := $(SRCDIR)/loggerfs_main.o $(SRCDIR)/operations.o

# Compiler Flags
CFLAGS := -std=gnu11 -Wno-declaration-after-statement -O3 -g

# Module configuration
obj-m += $(MODNAME).o
$(MODNAME)-y += $(SRC)

ifeq ($(DEBUG), 1)
CFLAGS += -DDEBUG
endif

# Targets
.PHONY: all app clean load unload create-fs mount-fs

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)" -j

app:
	gcc $(SRCDIR)/makelogfs.c -o makelogfs

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers
	rm -f makelogfs
	rm -rf ./mount

load:
	@echo "$(MODNAME) Loading..."
	sudo insmod $(MODNAME).ko

unload:
	@echo "$(MODNAME) Unloading..."
	if [ -d "./mount" ]; then sudo umount ./mount; fi
	sudo rmmod $(MODNAME)


create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./makelogfs image
	@if [ ! -d "./mount" ]; then mkdir ./mount; fi


mount-fs:
	sudo mount -o loop -t logfs image ./mount/

remove:
	@if lsmod | grep -q $(MODNAME); then sudo umount ./mount; fi
	@if [ -d "./mount" ]; then rm -rf ./mount; fi
	@if [ -f "image" ]; then rm -f image; fi
