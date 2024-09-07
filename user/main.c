//
// Created by effi on 01/09/24.
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "../include/state.h"
#include "../include/kremfip.h"
#include "../include/misc.h"
int main(int argc, char *argv[]) {
	rm_state_t state;
	int ret;

	ret = state_get(&state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("Current state: %s\n", state_to_str(state));
	return 0;
}