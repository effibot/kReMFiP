//
// Created by effi on 01/09/24.
//

#define DEBUG

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include "../src/include/kremfip.h"
#include "../src/utils/misc.h"

int main(int argc, char *argv[]) {
	state_t *state;
	state = calloc(1, sizeof(state_t));
	int ret;
	printf("euid: %d\n", geteuid());
	ret = state_get(state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("euid: %d\n", geteuid());
	printf("%d\n", *state);
	printf("Current state: %s\n", state_to_str(*state));
	state_t new_state = REC_ON;
	ret = state_set(&new_state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	ret = state_get(state);
	printf("New state: %s\n", state_to_str(*state));
	printf("euid: %d\n", geteuid());
	return 0;
	char *path = "/home/effi/file0.txt";
	path_op_t op = PROTECT_PATH;
	ret = reconfigure(&op, path);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("Reconfigured\n");
	new_state = REC_OFF;
	ret = state_set(&new_state);
	ret = reconfigure(&op, path);
	return 0;
}
