#include "misc.h"
#ifdef __KERNEL__
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#else
#include <string.h>
#endif
inline char *state_to_str(const state_t state) {
	switch (state) {
	case OFF:
		return "OFF";
	case ON:
		return "ON";
	case REC_OFF:
		return "REC_OFF";
	case REC_ON:
		return "REC_ON";
	default:
		return "UNKNOWN";
	}
}

inline state_t str_to_state(const char *state_str) {
	if (strcmp(state_str, "OFF") == 0) {
		return OFF;
	}
	if (strcmp(state_str, "ON") == 0) {
		return ON;
	}
	if (strcmp(state_str, "REC_OFF") == 0) {
		return REC_OFF;
	}
	if (strcmp(state_str, "REC_ON") == 0) {
		return REC_ON;
	}
	return -1;
}

/**
 * @brief Check if the state is valid
 * Perform a check on the state value to see if it's inside the range [0,3] = {OFF, ON, REC_OFF, REC_ON}
 * @param state
 * @return bool
 */
inline int is_state_valid(const state_t state) {
	return state == OFF || state == ON || state == REC_OFF || state == REC_ON;
}
int is_op_valid(const path_op_t op) {
	return op == PROTECT_PATH || op == UNPROTECT_PATH;
}

#ifdef __KERNEL__

/**
 * @brief Generates a random ID.
 *
 * This function generates a random ID between 1 and 32 inclusive.
 * It uses the `get_random_bytes` function to obtain a random number,
 * and then maps this number to the range [1, 32].
 *
 * @return A random unsigned int between 1 and 32.
 */
unsigned int rnd_id(void) {
	unsigned random_ticket;
	get_random_bytes(&random_ticket, sizeof(random_ticket));
	return 1u + (random_ticket % 32u);
}

/**
 * @brief Converts a byte array to a hex string.
 *
 * This function converts a byte array to a hex string.
 * It allocates memory for the string, so the caller is responsible
 * for freeing it when it is no longer needed.
 *
 * @param hex The byte array to convert.
 * @param len The length of the byte array.
 * @return A hex string representation of the byte array.
 */
inline char *hex_to_str(const unsigned char *hex, const size_t len) {
	// be sure the hex string is not empty
	if (strlen((char *)hex) == 0) {
		return NULL;
	}
	// allocate the string -- 2 hex characters for each byte
	char *str = kzalloc(len * 2 + 1, GFP_KERNEL);
	size_t i;
	for (i = 0; i < len; i++) {
		sprintf(&str[i * 2], "%02x", hex[i]);
	}
	str[len * 2] = '\0'; // null terminate the string
	return str;
}

/**
 * @brief Map user space buffer to kernel space.
 * @param ubuff The user space buffer
 * @param len The length of the buffer in terms of bytes.
 * This depends on the type of the buffer and the caller must calculate it correctly.
 * @return The kernel space buffer or an error code
 */
inline void *map_user_buffer(const void __user *ubuff, size_t len) {
	INFO("mapping user buffer to kernel space\n");
	// safety checks
	if (ubuff == NULL) {
		return ERR_PTR(-EINVAL);
	}
	int ret;
	// allocate the kernel space buffer
	void *kbuff = kmalloc(len * sizeof(void), GFP_KERNEL);
	if (kbuff == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	// copy the user space buffer to the kernel space buffer
	ret = copy_from_user(kbuff, ubuff, len);
	asm __volatile__("mfence" ::: "memory");
	if (ret != 0) {
		kfree(kbuff);
		return ERR_PTR(-EFAULT);
	}
	// return the kernel space buffer
	return kbuff;
}

#endif
