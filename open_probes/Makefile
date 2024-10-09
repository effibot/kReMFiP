obj-m:=open_probes.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="-g -O0 -std=gnu11"

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	$(MAKE) all
	sudo insmod open_probes.ko

unload:
	sudo rmmod open_probes.ko
	$(MAKE) clean