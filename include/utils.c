#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/unistd_64.h>

#include "types.h"
#include "utils.h"

static rm_t *rm_init(void){
	rm_t *rm = (rm_t *) kmalloc(sizeof(rm_t), GFP_KERNEL);
	rm->allowed_modes = al_mode_t;
	rm->blocked_modes = 0;
	rm->hooked_functions = hooked_functions;
	return rm;
}

static int rm_free(rm_t *rm){
	return kfree(rm);
}

