/**
 * @file rm_state.h
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Status declaration for the reference monitor
 * @version 0.1
 * @date 2024-07-30
 *
 * @copyright Copyright (c) 2024
 *
 */


#ifndef RM_STATE_H
#define RM_STATE_H
#include <linux/types.h>

typedef enum _rm_state {
	ON = 0,
	OFF = 1,
	REC_ON = 2,
	REC_OFF = 3
} state;


inline int rm_state_to_int(state s) {
	return (int)s;
}

inline state rm_int_to_state(int i) {
	return (state)i;
}

inline bool are_ops_on(state s) {
	if (s == ON || s == REC_ON) {
		return true;
	}
	return false;
}

inline bool is_reconfig(state s) {
	if (s == REC_ON || s == REC_OFF) {
		return true;
	}
	return false;
}

#endif