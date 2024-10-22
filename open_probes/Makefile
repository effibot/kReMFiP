obj-m:=open_probes.o

all:
	$(MAKE) -j4 -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules EXTRA_CFLAGS="-g -O0 -std=gnu11 -Wno-declaration-after-statement -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-value -Wno-unused-label -Wno-unused-parameter" 

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	$(MAKE) all
	sudo insmod open_probes.ko

unload:
	sudo rmmod open_probes.ko
	$(MAKE) clean