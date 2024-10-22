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
#include "../scth/headers/scth_lib.h"

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
	state_t *state;
	state = calloc(1, sizeof(state_t));
	int ret;
	ret = state_get(state);
	if (ret < 0) {
			printf("Error: %s\n", strerror(errno));
			return -1;
	}
	//int ret;
	//// be sure that the monitor is reconfigurable
	state_t new_state = REC_ON;
	ret = state_set(&new_state);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	// get state again
	state_get(state);
	printf("State set to %d\n",*state);
	// reconfigure
	char *path = calloc(1024, sizeof(char));
	printf("Enter the path to reconfigure: ");
	scanf("%s", path);
	path_op_t op = PROTECT_PATH;
	ret = reconfigure(&op, path);
	if (ret < 0) {
		printf("Error: %s\n", strerror(errno));
//		return -1;
	}
	printf("Reconfigured for path %s\n", path);
	free(state);
//	// try to open the file with rd only and wr perm
//	FILE* f = fopen(path, "r");
//	if (!f) {
//		printf("error: %s\n", strerror(errno));
//		exit(1);
//	}
//	char content[1024];
//	while(fgets(content, 1024, f) != NULL){
//		printf("Content: %s\n", content);
//	}
//	// close
//	fclose(f);
//	// now try to write
//	f = fopen(path, "r+");
//	if (!f) {
//		printf("error: %s\n", strerror(errno));
//		exit(1);
//	}
//	char* test = "test";
//	int num_byte =fwrite(test, strlen(test), 1, f);
//	if(num_byte <0)
//		exit(1);
	return 0;
}
