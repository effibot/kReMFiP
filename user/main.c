//
// Created by effi on 01/09/24.
//

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "../include/kremfip.h"
#include "../include/misc.h"
#include "../include/state.h"
int main(int argc, char *argv[]) {
	rm_state_t *state;
	state = calloc(1, sizeof(rm_state_t));
	int ret;

	ret = state_get(state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("%d\n", *state);
	printf("Current state: %s\n", state_to_str(*state));
	rm_state_t new_state = REC_OFF;
	ret = state_set(&new_state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("New state: %s\n", state_to_str(state_get(state)));
	new_state = ON;
	state_set(&new_state);
	printf("New state: %s\n", state_to_str(state_get(state)));

	return 0;
}