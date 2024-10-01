/**
 * @brief Source file for the "System Call Table Hacker" library.
 *        See related header file.
 *
 * @author Andrea Efficace <andrea.efficace1@gmail.com>
 *
 * @date February 8, 2021
 */

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>

// Add headers to navigate the PTs and check the mapping.
#include "../utils/paging_navigator.h"
#include "../utils/x86_utils.h"
// Add the header for the library.
#include "scth.h"
// link function implementation to external library headers.
#include "../../headers/scth_lib.h"

#include <linux/fs.h>
/**
 * @brief Mutex to ensure atomic operations on the system call table.
 * Is defined in the header file to be visible to every module.
 */
extern struct mutex scth_lock;

/* Total legit entries in the table (get this from "syscall_64.tbl" file). */
int tab_entries = 256;
module_param(tab_entries, int, S_IRUGO);
MODULE_PARM_DESC(tab_entries, "Number of legit entries in the system call table.");

/* Exposed addresses (for the root user only). */
unsigned long sys_call_table_addr = 0x0ULL;
unsigned long sys_ni_syscall_addr = 0x0ULL;
module_param(sys_call_table_addr, ulong, S_IRUSR | S_IRGRP);
module_param(sys_ni_syscall_addr, ulong, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(sys_call_table_addr, "Virtual address of the system call table.");
MODULE_PARM_DESC(sys_ni_syscall_addr, "Virtual address of the \"ni\" syscall.");

/* Array of known "ni" entries in the table. The more, the better.*/
int known_sysnis[] = { 134, 174, 182, 183, 214, 215, 236 };
unsigned int nr_known_sysnis = 7;
module_param(nr_known_sysnis, int, S_IRUGO);
module_param_array(known_sysnis, int, &nr_known_sysnis, S_IRUGO);
MODULE_PARM_DESC(nr_known_sysnis, "Number of entries pointing to \"ni\" syscall.");
MODULE_PARM_DESC(known_sysnis, "Indexes of entries pointing to \"ni\" syscall.");

/* Array of discovered "ni" entries in the table, ready to be hacked. */
struct scth_entry *avail_sysnis = NULL;
int nr_sysnis = 0;
module_param(nr_sysnis, int, S_IRUGO);
MODULE_PARM_DESC(nr_sysnis, "Number of hackable entries in the syscall table.");

// Internal functions prototypes
void scth_scan_table(void **table_addr);
int scth_pattern_check(void **addr);
int scth_prev_area_check(void **addr);
void **scth_check_page(void *pg);

// Internal functions implementation.

/**
 * @brief Scans the system call table and determines which entries can be hacked later.
 * It populates the "avail_sysnis" array with the indexes of the entries that point to "ni_syscall".
 * The array is then used to perform the actual hacking from the library's interface.
 *
 * @param table_addr Virtual address of the system call table.
 */
void scth_scan_table(void **table_addr) {
	int ni_count = 0;
	const void *first_sysni = table_addr[known_sysnis[0]];
	int i, j = 0;
	// First pass: determine how many entries there are.
	for (i = known_sysnis[0]; i < tab_entries; i++)
		if (table_addr[i] == first_sysni)
			ni_count++;
	// Allocate the array of entries.
	avail_sysnis = (struct scth_entry *)kzalloc(ni_count * sizeof(struct scth_entry), GFP_KERNEL);
	nr_sysnis = ni_count;
	// Second pass: populate the array.
	for (i = known_sysnis[0]; i < tab_entries; i++) {
		if (table_addr[i] == first_sysni) {
			avail_sysnis[j].tab_index = i;
			j++; // Increment only if we found a "ni" entry.
		}
	}
}

/**
 * @brief Checks whether a candidate address could point to the system call
 * table by looking at the entries we know should point to "ni_syscall".
 *
 * @param addr Virtual address to check.
 * @return Yes or no.
 */
int scth_pattern_check(void **addr) {
	const void *first_sysni = addr[known_sysnis[0]];
	for (int i = 1; i < nr_known_sysnis; i++)
		if (addr[known_sysnis[i]] != first_sysni)
			return 0;
	return 1;
}

/**
 * @brief Checks whether a candidate address could point to the system call
 * table by ensuring that "ni_syscall" is pointed only where it should be,
 * especially not before the first entry we know.
 *
 * @param addr Virtual address to check.
 * @return Yes or no.
 */
int scth_prev_area_check(void **addr) {
	for (int i = 0; i < known_sysnis[0]; i++)
		if (addr[i] == addr[known_sysnis[0]])
			return 0;
	return 1;
}

/**
 * @brief Checks whether a given page could contain (part of) the system call
 * table, performing a linear pattern matching scan. Returns the table base
 * address, if found.
 *
 * @param pg Virtual address of the page to check.
 * @return Virtual base address of the UNISTD_64 system call table.
 */
void **scth_check_page(void *pg) {
	// Loop over the page, checking for the pattern.
	for (unsigned long i = 0; i < __PAGE_SIZE; i += sizeof(void *)) {
		// If the table may span over two pages, check the second one.
		void *sec_page = pg + i + known_sysnis[nr_known_sysnis - 1] * sizeof(void *);
		if ((ulong)(pg + __PAGE_SIZE) == ((ulong)sec_page & __PAGE_MASK) &&
			paging_navigator((unsigned long)sec_page) == NOMAP)
			return NULL;
		// Now we can only go for pattern matching.
		void **candidate = pg + i;
		if (/* Check if the first known entry is not NULL. */
			candidate[known_sysnis[0]] != 0x0 &&
			/* Check for alignment. */
			((ulong)candidate[known_sysnis[0]] & 0x3) == 0x0 &&
			/* Check if it's in the kernel space. */
			candidate[known_sysnis[0]] > KERNEL_START_ADDR &&
			/* Check for the pattern. */
			scth_pattern_check(candidate) &&
			/* Check for the previous area. */
			scth_prev_area_check(candidate))
			// If all checks pass, we found the table.
			return candidate;
	}
	return NULL;
}

// Library functions implementation.

/**
 * @brief Restores all the entries in the table.
 */
void scth_cleanup(void) {
	unsigned long flags;
	void **table_addr = (void **)sys_call_table_addr;
	// grab the lock to avoid concurrent access.
	mutex_lock(&scth_lock);
	// Look if we have entries to restore, otherwise return.
	if (avail_sysnis == NULL) {
		mutex_unlock(&scth_lock);
		return;
	}
	// Restore all the entries that have been hacked.
	int i;
	for (i = 0; i < nr_sysnis; i++) {
		// We know if an entry has been hacked with the structure's flag.
		if (avail_sysnis[i].hacked) {
			// Disable write protection, replace the entry, and re-enable it.
			__x86_wp_disable(flags);
			table_addr[avail_sysnis[i].tab_index] = (void *)sys_ni_syscall_addr;
			// Ensure the write is visible to all CPUs before re-enabling WP.
			MFENCE;
			__x86_wp_enable(flags);
			printk(KERN_INFO "%s: Restored entry %d.\n", MODNAME, avail_sysnis[i].tab_index);
		}
	}
	// Free the array and release the lock.
	kfree(avail_sysnis);
	avail_sysnis = NULL;
	mutex_unlock(&scth_lock);
	printk(KERN_INFO "%s: System call table restored.\n", MODNAME);
}
EXPORT_SYMBOL(scth_cleanup);

/**
 * @brief Replaces a free entry in the table with a pointer to some other
 * function. In case of success, the index of the new entry is returned.
 * @remark Is the caller's responsibility to ensure that the new entry is a valid pointer
 * and that the index is within the bounds of the table. Moreover, the caller have to be sure that
 * the function pointer is effectively a system call.
 *
 * @param new_call_addr Pointer to replace.
 * @return Index of the new system call, or -1 if there's no room left.
 */
int scth_hack(void *new_call_addr) {
	int new_call_index;
	unsigned long flags;
	void **table_addr = (void **)sys_call_table_addr;
	// Grab the lock to avoid concurrent access.
	mutex_lock(&scth_lock);
	// Look if we have available entries, otherwise return.
	if (avail_sysnis == NULL) {
		mutex_unlock(&scth_lock);
		return -1;
	}
	// Look for a free entry to replace.
	int i;
	for (i = 0; i < nr_sysnis; i++) {
		// We can hack only not already hacked entries.
		if (!avail_sysnis[i].hacked) {
			new_call_index = avail_sysnis[i].tab_index;
			// Disable write protection, replace the entry, and re-enable it.
			__x86_wp_disable(flags);
			table_addr[new_call_index] = new_call_addr;
			// Ensure the write is visible to all CPUs before re-enabling WP.
			MFENCE;
			__x86_wp_enable(flags);
			avail_sysnis[i].hacked = 1;
			printk(KERN_INFO "%s: Hacked entry %d.\n", MODNAME, new_call_index);
			mutex_unlock(&scth_lock);
			return new_call_index;
		}
	}
	mutex_unlock(&scth_lock);
	return -1;
}
EXPORT_SYMBOL(scth_hack);

/**
 * @brief Restores an entry in the table.
 *
 * @param to_restore Index of the entry to restore.
 */
void scth_unhack(int to_restore) {
	unsigned long flags;
	void **table_addr = (void **)sys_call_table_addr;
	// Grab the lock to avoid concurrent access.
	mutex_lock(&scth_lock);
	// Consistency check on input arguments.
	if (to_restore < 0 || avail_sysnis == NULL) {
		goto exit;
	}
	// Look for the entry to restore.
	int i;
	for (i = 0; i < nr_sysnis; i++) {
		// We double-check that the entry to restore is valid and has been hacked.
		if (avail_sysnis[i].tab_index == to_restore && avail_sysnis[i].hacked) {
			// unmark the entry as hacked.
			avail_sysnis[i].hacked = 0;
			// Disable write protection, restore the entry, and re-enable it.
			__x86_wp_disable(flags);
			table_addr[to_restore] = (void *)sys_ni_syscall_addr;
			// Ensure the write is visible to all CPUs before re-enabling WP.
			MFENCE;
			__x86_wp_enable(flags);
			printk(KERN_INFO "%s: Restored entry %d.\n", MODNAME, to_restore);
			goto exit;
		}
	}
exit:
	mutex_unlock(&scth_lock);
}
EXPORT_SYMBOL(scth_unhack);

/**
 * @brief Looks for the system call table searching kernel memory in a linear fashion.
 * It relies on, together with previous routines, the following assumptions:\n
 * 1- We can start the search at KERNEL_START_ADDR.\n
 * 2 - When the kernel image is loaded in memory, relative offsets between
 *     elements aren't randomized even if KASLR or similar are enabled.\n
 * 3 - Table entries are 8-bytes long and aligned. \n
 * 4 - Entries in "known_sysnis" point to "ni_syscall". Since layout is
 *     subject to change over time, check the "syscall_64.tbl".\n
 *
 * @return UNISTD_64 system call table virtual address, or 0 if search fails.
 */
void **scth_finder(void) {
	void **addr;
	for (void *pg = KERNEL_START_ADDR; pg < KERNEL_END_ADDR; pg += __PAGE_SIZE) {
		// Do a simple linear search in the canonical higher half of virtual
		// memory, previously checking that the target address is mapped to
		// avoid General Protection Errors, page by page.
		if (paging_navigator((unsigned long)pg) != NOMAP && (addr = scth_check_page(pg)) != NULL) {
			printk(KERN_INFO "%s: UNISTD_64 system call table found at: 0x%px.\n", MODNAME, addr);
			sys_call_table_addr = (unsigned long)addr;
			sys_ni_syscall_addr = (unsigned long)addr[known_sysnis[0]];
			scth_scan_table(addr);
			return addr;
		}
	}
	printk(KERN_ERR "%s: UNISTD_64 system call table not found.\n", MODNAME);
	return NULL;
}
EXPORT_SYMBOL(scth_finder);


/**
 * @brief Returns the array of known indexes pointing to "ni_syscall".
 * As this is a User interface, we don't want to expose the internal array, we use the
 * sysfs interface to return the array of known indexes.
 * @return Array of known indexes.
 */
int *scth_get_sysnis(void) {
	// Be sure that the module is loaded and the array is populated.
	if (avail_sysnis == NULL)
		return NULL;
	// Just to be sure, grab the lock
	mutex_lock(&scth_lock);
	char *buf = (char *)kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		printk(KERN_ERR "%s: Failed to allocate memory for the buffer.\n", MODNAME);
		return NULL;
	}
	// Read from the sysfs file
	struct file *f = filp_open("/sys/kernel/scth/sysnis", O_RDONLY, 0);
	if (IS_ERR(f)) {
		printk(KERN_ERR "%s: Failed to open the sysfs file.\n", MODNAME);
		kfree(buf);
		return NULL;
	}
	// Read the file content.
	const ssize_t bytes_read = kernel_read(f, buf, PAGE_SIZE, &f->f_pos);
	if (bytes_read < 0) {
		printk(KERN_ERR "%s: Failed to read the sysfs file.\n", MODNAME);
		kfree(buf);
		filp_close(f, NULL);
		return NULL;
	}
	// Close the file
	filp_close(f, NULL);

	// Count the number of hacked entries.
	int j = 0;
	for (int i = 0; i < nr_sysnis; i++)
		if (avail_sysnis[i].hacked)
			j++;
	// Prepare the buffer to return.
	int *sysnis = kzalloc(j * sizeof(int), GFP_KERNEL);
	if (sysnis == NULL) {
		printk(KERN_ERR "%s: Failed to allocate memory for the array.\n", MODNAME);
		kfree(buf);
		return NULL;
	}
	// Fill the array with the indexes of the hacked entries.
	for (int i = 0, k = 0; i < nr_sysnis; i++)
		if (avail_sysnis[i].hacked)
			sysnis[k++] = avail_sysnis[i].tab_index;

	return sysnis;
}
