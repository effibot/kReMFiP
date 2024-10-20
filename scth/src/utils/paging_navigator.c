/**
 * This is free software.
 * You can redistribute it and/or modify this file under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 * 
 * This file is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this file; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.
 */
/**
 * @brief Source code for the "page_navigator" routine.
 *        See related header file.
 *
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 *
 * @date August 31, 2024
 */

#define EXPORT_SYMTAB
#include <asm/page.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>

// Add our x86 cr3 manipulation functions.
#include "x86_utils.h"
// Proper header file
#include "paging_navigator.h"

#define MODNAME "PAGING_NAVIGATOR"

// Constants - ULL suffix is used to force u64-bit integer type.
#define CR3_MASK 0xfffffffffffff000ULL
#define PT_ADDR_MASK 0x7ffffffffffff000ULL
#define PRESENT 0x1ULL
#define L_PAGE 0x80ULL
// Get the page table structures by shifting the virtual address and masking.
#define PML4(vaddr) ((unsigned long long)(vaddr >> 39) & 0x1ffULL)
#define PDP(vaddr) ((unsigned long long)(vaddr >> 30) & 0x1ffULL)
#define PDE(vaddr) ((unsigned long long)(vaddr >> 21) & 0x1ffULL)
#define PTE(vaddr) ((unsigned long long)(vaddr >> 12) & 0x1ffULL)

/**
 * @brief Traverses the page table to check if a given virtual address
 * is mapped onto some physical frame. Helps to prevent General Protection Errors.
 *
 * @param vaddr Virtual address to check.
 * @return Physical frame number, or NOMAP.
 */
long paging_navigator(unsigned long vaddr) {
	// Page table structures.
	pgd_t *pml4;
	pud_t *pdp;
	pmd_t *pde;
	pte_t *pte;

	long frame_num;

#ifdef DEBUG
	printk(KERN_DEBUG "%s: Asked to check address: 0x%px.\n", MODNAME, (void *)vaddr);
#endif

	// Get PML4 table virtual address translating CR3's content.
	pml4 = __va(__x86_read_cr3() & CR3_MASK);
#ifdef DEBUG
	printk(KERN_DEBUG "%s: PML4 table is at: 0x%px.\n", MODNAME, pml4);
#endif

	// Check PML4 table entry.
	if (!(pml4[PML4(vaddr)].pgd & PRESENT)) {
#ifdef DEBUG
		printk(KERN_DEBUG "%s: PML4 entry not present.\n", MODNAME);
#endif
		goto unmapped;
	}
	// Get PDP table virtual address.
	pdp = __va((pml4[PML4(vaddr)].pgd) & PT_ADDR_MASK);
#ifdef DEBUG
	printk(KERN_DEBUG "%s: PDP table is at: 0x%px.\n", MODNAME, pdp);
#endif

	// Check PDP table entry.
	// NOTE: This could, someday, host a mapping to a 1 GB page.
	if (!(pdp[PDP(vaddr)].pud & PRESENT)) {
#ifdef DEBUG
		printk(KERN_DEBUG "%s: PDP entry not present.\n", MODNAME);
#endif
		goto unmapped;
	}
	// Check if the PDP entry maps a 1 GB page.
	if (unlikely((pdp[PDP(vaddr)].pud) & L_PAGE)) {
#ifdef DEBUG
		printk(KERN_DEBUG "%s: PDP entry maps 1 GB page.\n", MODNAME);
#endif
		frame_num = (pdp[PDP(vaddr)].pud & PT_ADDR_MASK) >> 30;
		goto mapped;
	}
	// Get PD table virtual address.
	pde = __va((pdp[PDP(vaddr)].pud) & PT_ADDR_MASK);
#ifdef DEBUG
	printk(KERN_DEBUG "%s: PD is at: 0x%px.\n", MODNAME, pde);
#endif

	// Check PD entry.
	// NOTE: This could host a mapping to a 2 MB page.
	if (!(pde[PDE(vaddr)].pmd & PRESENT)) {
#ifdef DEBUG
		printk(KERN_DEBUG "%s: PD entry not present.\n", MODNAME);
#endif
		goto unmapped;
	}
	// Check if the PD entry maps a 2 MB page.
	if (unlikely((pde[PDE(vaddr)].pmd) & L_PAGE)) {
#ifdef DEBUG
		printk(KERN_DEBUG "%s: PD entry maps 2 MB page.\n", MODNAME);
#endif
		frame_num = (pde[PDE(vaddr)].pmd & PT_ADDR_MASK) >> 21;
		goto mapped;
	}
	pte = __va((pde[PDE(vaddr)].pmd) & PT_ADDR_MASK);
#ifdef DEBUG
	printk(KERN_DEBUG "%s: PT is at: 0x%px.\n", MODNAME, pte);
#endif

	// Check PT entry.
	if (!(pte[PTE(vaddr)].pte & PRESENT)) {
#ifdef DEBUG
		printk(KERN_DEBUG "%s: PT entry not present.\n", MODNAME);
#endif
		goto unmapped;
	}
	frame_num = (pte[PTE(vaddr)].pte & PT_ADDR_MASK) >> 12;
#ifdef DEBUG
	printk(KERN_DEBUG "%s: Found mapping at frame: %ld.\n", MODNAME, frame_num);
#endif
mapped:
	return frame_num;
unmapped:
	return NOMAP;
}
