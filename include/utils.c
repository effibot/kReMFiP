#include <linux/random.h>
#include "utils.h"

/**
 * @brief Generates a random ID.
 *
 * This function generates a random ID between 1 and 32 inclusive.
 * It uses the `get_random_bytes` function to obtain a random number,
 * and then maps this number to the range [1, 32].
 *
 * @return A random unsigned int between 1 and 32.
 */
int rnd_id(void) {
    unsigned random_ticket;
    get_random_bytes(&random_ticket, sizeof(random_ticket));
    return 1u + (random_ticket % 32u);
}

char *get_state_str(rm_state_t state) {
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

/**
 * @brief Check if the state is valid
 * Perform a check on the state value to see if it's inside the range [0,3] = {OFF, ON, REC_OFF, REC_ON}
 * @param state
 * @return bool
 */
bool is_state_valid(rm_state_t state) {
    return state >= OFF && state <= REC_ON;
}