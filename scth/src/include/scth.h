/**
 * @brief Header file for the "System Call Table Hacker" library.
 *        A small set of routines that track the position of the Table in
 *        kernel memory and provide interfaces to replace its entries, and
 *        then restore them.
 *        This library exposes the following functions, plus some module
 *        parameters that you can find in the related source file. Some of them
 *        may be specified at boot to reconfigure the table search.
 *
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 *
 * @date August 31, 2024
 */

#ifndef SCT_HACKER_H
#define SCT_HACKER_H
// for internal use
#ifndef MODNAME
#define MODNAME "SCTH"
#endif
// Page size and mask.
#define __PAGE_SIZE 4096
#define __PAGE_MASK 0xfffffffffffff000ULL

/**
 * Virtual kernel memory addresses at which the search starts and ends.
 * Note that this search covers 4 GiB of the kernel virtual address space,
 * where we expect to find the kernel's data segment as loaded at boot as
 * per the System.map contents nowadays.
 */
#define KERNEL_START_ADDR ((void *)0xffffffff00000000ULL)
#define KERNEL_END_ADDR ((void *)0xfffffffffff00000ULL)

#define MFENCE asm volatile("sfence" ::: "memory")

// Structure to hold information about a hackable entry in the table.
struct scth_entry {
	int tab_index;
	unsigned char hacked : 1;
};

// Library functions prototypes.
void **scth_finder(void);
void scth_cleanup(void);
int scth_hack(void *new_call_addr);
void scth_unhack(int to_restore);

#endif
