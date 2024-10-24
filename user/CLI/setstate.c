#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "../../src/user/kremfip_lib.h"
#include "../../src/utils/misc.h"

/**
 * @brief Program to generate a CLI to let the user
 * interact with the reference monitor and change its state.
 * Accepted states are OFF, ON, REC_OFF, REC_ON
 */

int main(int argc, char *argv[]){
	// As appropriate checks are performed in the setstate function,
	// we don't need to check the state here.
	// Actually, we don't need to check for the exsitence of the path either.

	// we need 2 arguments to set the state of the monitor
	if(argc != 3){
		printf("Usage: %s -s <state>\n"
			   "Accepted states, as int or strings, are\n"
			   "0 (OFF), 1 (ON), 2 (REC_OFF), 3 (REC_ON)\n"
			   , argv[0]);
		return -1;
	}
	// Now parse the arguments
	if(strcmp(argv[1], "-s") != 0){
		printf("Usage: %s -s <state>\n"
			   "Accepted states, as int or strings, are\n"
			   "0 (OFF), 1 (ON), 2 (REC_OFF), 3 (REC_ON)\n"
			   , argv[0]);
		return -1;
	}
	// Get the state from the argument
	state_t state;
	if(strlen(argv[2]) == 1){
		state = atoi(argv[2]);
	}else{
		state = str_to_state(argv[2]);
	}
	// check if the state is valid
	if (state < 0 || state > 3){
		printf("Invalid state: %s\n", argv[2]);
		return -1;
	}

	// Call the syscall
	int err = state_set(&state);
	if(err < 0){
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("State set to %s\n", state_to_str(state));
	return 0;
}
