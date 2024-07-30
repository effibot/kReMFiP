/**
 * @file kremfip_main.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Main file for the kReMFiP project
 * @version 0.1
 * @date 2024-07-29
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

# include "include/rm_state.h"
// just to test stuffs because don't programming in C for a while
typedef struct _rm_t {
	state status;
} rm_t;

rm_t *rm_init() {
	rm_t *X = malloc(sizeof(rm_t));
	if (X == NULL) {
		perror("malloc");
		return NULL;
	}
	X->status = OFF;
	return X;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s <command>\n", argv[0]);
		return 1;
	}
	rm_t *X = rm_init();

	if (X == NULL) {
		perror("malloc");
		return 1;
	}
	//X->status = OFF;
	printf("Status: %d\n", X->status);
	return 0;
}