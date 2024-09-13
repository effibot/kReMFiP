/**
 * @brief Header file for the "paging_navigator" routine.
 *        Tells if a paged virtual address is mapped on a physical frame, and
 *        in case returns the corresponding physical frame number.
 *        Works on x86-64 machines in long mode with 4-level paging.
 *        Based on the `vtpmo.c` from [Linux Syscall Table Discover]
 *        (https://github.com/FrancescoQuaglia/Linux-sys_call_table-discoverer)
 *
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 *
 * @date August 31, 2024
 */

#ifndef PAGING_NAVIGATOR_H
#define PAGING_NAVIGATOR_H

#define NOMAP -1

long paging_navigator(unsigned long vaddr);

#endif
