#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "../../src/user/kremfip_lib.h"
#include "../../src/utils/misc.h"

/**
 * @brief Program to generate a CLI to let the user
 * interact with the reference monitor and reconfigure the monitor.
 * Reconfiguring means that we can add or remove a path from the monitor.
 * we need two arguments to reconfigure the monitor
 * -o: the operation to perform, either 0 (PROTECT_PATH) or 1 (UNPROTECT_PATH)
 * -p: the path to reconfigure, either absolute or relative
 */

int main(int argc, char *argv[]){
	// As appropriate checks are performed in the reconfigure function,
	// we don't need to check the state here.
	// Actually, we don't need to check for the exsitence of the path either.

	// we need 4 arguments to reconfigure the monitor
	if(argc != 5){
		printf("Usage: %s -o <operation> -p <path>\n"
			   "Accepted operations, as int or strings, are\n"
			   "0 (PROTECT_PATH), 1 (UNPROTECT_PATH)\n"
			   , argv[0]);
		return -1;
	}
	// Now parse the arguments
	if(strcmp(argv[1], "-o") != 0 || strcmp(argv[3], "-p") != 0){
		printf("Usage: %s -o <operation> -p <path>\n"
			   "Accepted operations, as int or strings, are\n"
			   "0 (PROTECT_PATH), 1 (UNPROTECT_PATH)\n"
			   , argv[0]);
		return -1;
	}
	// Get the operation from the argument
	path_op_t op;
	if(strlen(argv[2]) == 1){
		op = atoi(argv[2]);
	}else{
		op = str_to_op(argv[2]);
	}
	// check if the op is valid
	if (op < 0 || op > 1){
		printf("Invalid operation: %s\n", argv[2]);
		return -1;
	}
	// Get the path from the argument
	char *path = argv[4];

	// Call the syscall
	int err = reconfigure(&op, path);
	if(err < 0){
		printf("Error: %s\n", strerror(errno));
		return -1;
	}
	printf("Path %s successfully\n", op == PROTECT_PATH ? "protected" : "unprotected");
	return 0;
}
