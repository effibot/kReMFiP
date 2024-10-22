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
.PHONY: all clean load unload create-fs mount-fs
#gcc logmakefs.c -o logmakefs

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(CFLAGS)" -j

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	@echo "$(MODNAME) Loading..."
	$(shell ./load.sh)

unload:
	@echo "$(MODNAME) Unloading..."
	$(shell ./unload.sh)

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./logmakefs image
	mkdir mount

mount-fs:
	mount -o loop -t singlefilefs image ./mount/
