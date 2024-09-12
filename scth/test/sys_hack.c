//
// Created by effi on 12/09/24.
//

// Include the library that is used to hack the kernel
#include "../src/include/scth.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/init.h>
// Define a simple system call that will be used to test the system call table hacking
__SYSCALL_DEFINEx(1, _test_syscall, int, arg) {
	printk(KERN_INFO "Test syscall invoked with arg: %d\n", arg);
	return 0;
}
int test_nr = -1;
struct module *scth_mod = NULL;

// Define the initialization routine for the module
static int __init sys_hack_init(void) {
	// Lock the SCTH module.
	mutex_lock(&module_mutex);
	scth_mod = find_module("SCTH");
	if (!try_module_get(scth_mod)) {
		mutex_unlock(&module_mutex);
		printk(KERN_ERR "%s: SCTH module not found.\n", MODNAME);
		return -EPERM;
	}
	mutex_unlock(&module_mutex);
	// the system call is exposed, we can hack it
	// Hack the system call table to point to the test syscall
	test_nr = scth_hack(__x64_sys_test_syscall);
	if (test_nr < 0) {
		printk(KERN_ERR "Failed to hack the system call table.\n");
		scth_cleanup();
		module_put(scth_mod);
		return -EPERM;
	}
	printk(KERN_INFO "Hacked system call table at index: %d\n", test_nr);
	return 0;
}

// Define the cleanup routine for the module
static void __exit sys_hack_exit(void) {
	// Unhack the system call table
	scth_unhack(test_nr);
	// Release the SCTH module
	module_put(scth_mod);
}
// Define module stuffs
#define TESTMODNAME "SCTH_TEST"
module_init(sys_hack_init);
module_exit(sys_hack_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
MODULE_DESCRIPTION("A simple module that tests the syscall table hacking process.");
MODULE_INFO(name, MODNAME);
MODULE_INFO(OS, "Linux");
MODULE_VERSION("1.0");