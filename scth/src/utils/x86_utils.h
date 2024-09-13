/**
 * @brief Header file for a small library of functions and macros to access
 *        control registers and perform some architecture-specific tasks on
 *        x86 machines.
 *        They're both defined and declared here since they're inlined, as
 *        static symbols to avoid compiler complaints about multiple
 *        definitions.
 * 
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * 
 * @date August 31, 2024
 */

#ifndef X86_UTILS_H
#define X86_UTILS_H

#include <linux/irqflags.h>

#define __X86_CR0_WP 0x10000

/**
 * @brief Reads the CR3 register on x86 CPUs. The function is inlined to calling overhead.
 * @note The $rax register is xor-ed to avoid any garbage in it.
 * @return Physical address of top level page table (PML4 on x86-64).
 */
static inline unsigned long __x86_read_cr3(void) __attribute__((always_inline));
static inline unsigned long __x86_read_cr3(void) {
	unsigned long cr3 = 0;
	asm volatile("xor %%rax, %%rax\n\t"
				 "mov %%cr3, %%rax\n\t"
				 : "=a"(cr3)
				 :
				 :);
	return cr3;
}

/**
 * @brief Disables Write Protection on x86 CPUs, clearing the WP bit in CR0.
 * @remark : To keep machine state consistent, this disables IRQs too, saving
 * their disabled state in the provided variable. Is meant to be used to circle
 * some really critical, deterministic, nonblocking and short code.
 *
 * @param flags unsigned long in which to store IRQ state.
 */
#define __x86_wp_disable(flags)                                                                    \
	do {                                                                                           \
		/* Save the current interrupt state and disable interrupts. */                             \
		local_irq_save(flags);                                                                     \
		asm volatile(                                                                              \
			"xor %%rax, %%rax\n\t" /* Clear the RAX register */                                    \
			"xor %%rbx, %%rbx\n\t" /* Clear the RBX register */                                    \
			"mov %%cr0, %%rax\n\t" /* Move the current value of the CR0 into RAX. */               \
			"mov %0, %%rbx\n\t" /* Move the WP bit mask (__X86_CR0_WP) into RBX. */                \
			"not %%rbx\n\t" /* Invert the bits in RBX to create a mask where the WP bit is 0. */   \
			"and %%rbx, %%rax\n\t" /* Clear the WP bit in RAX */                                   \
			"mov %%rax, %%cr0\n\t" /* Write the modified value in RAX back to the CR0 register. */ \
			: /* No output operands. */                                                            \
			: "i"(__X86_CR0_WP) /* Input operand: the WP bit (__X86_CR0_WP). */                    \
			: "rax", "rbx"); /* RAX and RBX registers are clobbered (used and modified). */        \
	} while (0)

/**
 * @brief Enables Write Protection on x86 CPUs, setting the WP bit in CR0.
 * @remark : According to its dual above, this enables IRQs, restoring the
 * saved state provided.
 *
 * @param flags unsigned long that holds IRQ state to restore.
 */
#define __x86_wp_enable(flags)                                                                          \
	do {                                                                                                \
		asm volatile(                                                                                   \
			"xor %%rax, %%rax\n\t" /* Clear the RAX register */                                         \
			"xor %%rbx, %%rbx\n\t" /* Clear the RBX register */                                         \
			"mov %%cr0, %%rax\n\t" /* Move the current value of the CR0 into RAX. */                    \
			"mov %0, %%rbx\n\t" /* Move the WP bit mask (__X86_CR0_WP) into RBX. */                     \
			"or %%rbx, %%rax\n\t" /* Set the WP bit in RAX */                                           \
			"mov %%rax, %%cr0\n\t" /* Write the modified value in RAX back to the CR0 register. */      \
			: /* No output operands. */                                                                 \
			: "i"(__X86_CR0_WP) /* Input operand: the WP bit (__X86_CR0_WP). */                         \
			: "rax", "rbx"); /* RAX and RBX registers are clobbered (used and modified). */             \
		/* Restore the saved interrupt state (re-enable interrupts if they were previously enabled). */ \
		local_irq_restore(flags);                                                                       \
	} while (0)

#endif
