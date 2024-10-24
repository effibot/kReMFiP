#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "../../src/user/kremfip_lib.h"
#include "../../src/utils/misc.h"

/**
 * @brief Program to generate a CLI to let the user
 * interact with the reference monitor know its state.
 */

int main(int argc, char *argv[]){
	// we need 1 argument to get the state of the monitor
	if(argc != 1){
		printf("Usage: %s\n", argv[0]);
		return -1;
	}
	// Call the syscall
	state_t state;
	int err = state_get(&state);
	if(err < 0){
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("The state of the monitor is %s\n", state_to_str(state));
	return 0;
}
