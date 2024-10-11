//
// Created by effi on 16/09/24.
//

#ifndef SCTH_LIB_H
#define SCTH_LIB_H
#ifdef __KERNEL__
// Library functions prototypes.
void **scth_finder(void);
void scth_cleanup(void);
int scth_hack(void *new_call_addr);
void scth_unhack(int to_restore);

#else

// This a userspace interface to retrieve the available indexes

#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SIZE 4096

#define SCTH_SYSNIS "/sys/module/scth/sysnis"
#define SCTH_HSYSNIS "/sys/module/scth/hsysnis"

/**
 * @brief Get the available indexes of the system calls that were hijacked by the module.
 * @param sys_file the file that contains the indexes of the system calls. This can be one of the following:
 * - /sys/module/scth/sysnis: if you want to get the indexes of the available system calls.
 * - /sys/module/scth/hsysnis: if you want to get the indexes of the hijacked system calls.
 * @param hidx the index of the system call to retrieve.
 * @return an array of integers containing the indexes of the system calls.
 */
static inline int get_sys_idx(const char* sys_file, int hidx) {
	/* If the module is loaded there is a file inside the /sys/module/scth directory
	 * called sysnis. This file contains the syscall numbers of the system calls
	 * that were hijacked by the module.*/
	FILE *sysnis = fopen(sys_file, "r");
	if (!sysnis) {
		fprintf(stderr, "Failed to open %s\n", sys_file);
		return NULL;
	}
	// we can't establish the number of available indexes, so we have to read the file and count.
	int avail_idx = 0, i = 0;
	char* buf = calloc(PAGE_SIZE, sizeof(char));
	// read the file and store the string in buf.
	if(fgets(buf, PAGE_SIZE, sysnis) == NULL) {
		fprintf(stderr, "Failed to read %s\n", sys_file);
		free(buf);
		fclose(sysnis);
		return NULL;
	}
	// close the stream and count the number of indexes.
	fclose(sysnis);
	char **token, *tmp;
	tmp = strdup(buf);
	// we know that the maximum size of the syscall table is 256.
	token = calloc(256, sizeof(char*));
	while((token[i] = strsep(&tmp, " ")) != NULL) {
		avail_idx++;
		i++;
	}
	free(tmp);
	// allocate memory for the indexes.
	int *sysnis_arr = calloc(avail_idx, sizeof(int));
	for (i = 0; i < avail_idx; i++) {
		sysnis_arr[i] = atoi(token[i]);
	}
	free(token);
	free(buf);
	// assert that the index is within the bounds.
	if (hidx < 0 || hidx >= avail_idx) {
		fprintf(stderr, "Index of hijacked syscall out of bounds\n");
		return -1;
	}
	int ret_hidx = sysnis_arr[hidx];
	free(sysnis_arr);
	return ret_hidx;
}


#endif

#endif //SCTH_LIB_H
