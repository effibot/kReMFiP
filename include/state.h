//
// Created by effi on 01/09/24.
//

#ifndef STATE_H
#define STATE_H
typedef enum _rm_state_t {
	OFF = 0,
	ON = 1,
	REC_OFF = 2,
	REC_ON = 3,
} rm_state_t;
typedef enum { PROTECT_PATH = 0, UNPROTECT_PATH = 1 } path_op_t;

#endif //STATE_H
