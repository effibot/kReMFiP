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

#include "../src/include/kremfip.h"
#include "../src/utils/misc.h"

int main(int argc, char *argv[]) {
	state_t *state;
	state = calloc(1, sizeof(state_t));
	int ret;

	ret = state_get(state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("%d\n", *state);
	printf("Current state: %s\n", state_to_str(*state));
    return 0;
	state_t new_state = REC_OFF;
	ret = state_set(&new_state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	ret = state_get(state);
	printf("New state: %s\n", state_to_str(*state));
	char *path = "/home/effi/file0.txt";
	path_op_t op = PROTECT_PATH;
	ret = reconfigure(&op, path);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("Reconfigured\n");
	return 0;
}
