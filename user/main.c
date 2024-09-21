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

// To get state:
/**
* state_t *state;
 state = calloc(1, sizeof(state_t));
 int ret;
 ret = state_get(state);
if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
*/

// To set state:
/**
* state_t new_state = REC_ON;
	ret = state_set(&new_state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
*/


int main(int argc, char *argv[]) {
	int ret;
	// be sure that the monitor is reconfigurable
	state_t new_state = REC_ON;
	ret = state_set(&new_state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("State set\n");
	char *path = "/home/effi/file0.txt";
	char *invalid_path = "/home/effi/file_i.txt";
	path_op_t op = PROTECT_PATH;
	ret = reconfigure(&op, path);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("Reconfigured for path %s\n", path);
	ret = reconfigure(&op, invalid_path);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
	}
	printf("end\n");
	return 0;
}
