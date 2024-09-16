#include "misc.h"
#ifdef __KERNEL__
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <crypto/hash.h>
#include <crypto/sha256_base.h>
#include <linux/fs.h>
#include <linux/types.h>
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
inline int is_op_valid(const path_op_t op) {
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
inline unsigned int rnd_id(void) {
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

/**
 * @brief Hash the password with the salt
 *
 * This function hashes the password with the salt using the SHA256 algorithm.
 * The hash is stored in the pwd_hash buffer. The salt is prepended to the password.
 * BEWARE: the password hash MUST be stored in the dedicated sysfs file and then
 * cleared from memory to avoid leaking traces of the password in the kernel space.
 *
 * @param pwd The password to hash
 * @param pwd_salt The salt to use for hashing
 * @param pwd_hash The buffer to store the hash
 * @return int 0 if the hash is computed successfully, an error code otherwise
 */

inline int hash_pwd(const char *pwd, const u8 *pwd_salt, u8 *pwd_hash) {
	// The password is set at the module load time. Checking for non-NULL value just to be sure.
	if (unlikely(pwd == NULL || strlen(pwd) == 0)) {
		INFO("Password is not set");
		return -EINVAL;
	}

	// concatenate the password and the salt
	const size_t salted_len = strlen(pwd) + RM_PWD_SALT_LEN;
	u8 *salted_pwd = kzalloc(salted_len, GFP_KERNEL);
	if (unlikely(salted_pwd == NULL)) {
		INFO("Failed to allocate memory for the salted password");
		return -ENOMEM;
	}
	// Add the salt at the head because is proven to be more secure
	memcpy(salted_pwd, pwd_salt, RM_PWD_SALT_LEN);
	memcpy(salted_pwd + RM_PWD_SALT_LEN, pwd,
		   strlen(pwd)); // pointers arithmetic

	// allocate memory for the hash - we use the SHA256 algorithm because yes
	struct crypto_shash *tfm = crypto_alloc_shash(RM_CRYPTO_ALGO, 0, 0);
	if (IS_ERR(tfm)) {
		INFO("Failed to allocate crypto shash");
		return PTR_ERR(tfm);
	}
	// allocate memory for the hash descriptor
	// Allocate descriptor for shash (synchronous hash)
	struct shash_desc *desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		printk(KERN_ERR "Failed to allocate shash descriptor\n");
		crypto_free_shash(tfm);
		kfree(salted_pwd);
		return -ENOMEM;
	}
	// Initialize the descriptor
	desc->tfm = tfm;

	// Initialize the hash descriptor
	int ret = crypto_shash_init(desc);
	if (ret) {
		printk(KERN_ERR "Hash initialization failed\n");
		goto out;
	}

	// Hash the salted password
	ret = crypto_shash_update(desc, salted_pwd, salted_len);
	if (ret) {
		printk(KERN_ERR "Hash update failed\n");
		goto out;
	}

	// Finalize the hash
	ret = crypto_shash_final(desc, pwd_hash);
	if (ret) {
		printk(KERN_ERR "Hash finalization failed\n");
	}
#ifdef DEBUG
	else {
		printk(KERN_INFO "Password hash with salt computed successfully\n");
	}
#endif

	// free the memory - we don't want to leak traces of the password
out:
	memzero_explicit(salted_pwd, salted_len);
	kfree(salted_pwd);
	memzero_explicit(desc, sizeof(*desc));
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

/**
 * @brief Verify the hash of the input string
 *
 * This function verifies the hash of the input string with the stored hash.
 * It computes the hash of the input string and compares it with the stored hash.
 *
 * @param input_str The input string to verify
 * @return true The hash of the input string matches the stored hash
 * @return false The hash of the input string does not match the stored hash
 */
extern u8 pwd_salt[]; // this changes at every module load, so we need to declare it as extern
inline bool verify_pwd(const char *input_str) {
	// Ensure the input string is not NULL
	INFO("Verifying the password");
	if (IS_ERR_OR_NULL(input_str)) {
		WARNING("Input string is NULL");
		return false;
	}
	// Hash the input string
	u8 *input_hash = kzalloc(RM_PWD_HASH_LEN*sizeof(u8), GFP_KERNEL);
	if (hash_pwd(input_str, pwd_salt, input_hash)) {
		WARNING("Failed to hash the input string");
		return false;
	}
	// Retrieve the stored hash from the sysfs
	struct file *f = filp_open(RM_PWD_HASH_PATH, O_RDONLY, 0);
	if (IS_ERR(f)) {
		WARNING("Failed to open the sysfs file");
		return false;
	}
	// Read the stored hash from the sysfs
	char *stored_hash;
	size_t stored_hash_len = RM_PWD_HASH_LEN * 2 + 1;
	stored_hash = kzalloc(stored_hash_len*sizeof(char), GFP_KERNEL);
	const ssize_t bytes_read = kernel_read(f, stored_hash, RM_PWD_HASH_LEN * 2, &f->f_pos);
	filp_close(f, NULL);
	if (bytes_read < 0) {
		WARNING("Failed to read the stored hash from the sysfs file");
		return false;
	}
	// Compare the hashes
	const bool cmp =
		memcmp(hex_to_str(input_hash, RM_PWD_HASH_LEN), stored_hash, RM_PWD_HASH_LEN) == 0;
#ifdef DEBUG
	INFO("Hashes compared successfully");
#endif
	// Clean up the stored hash
	memzero_explicit(stored_hash, stored_hash_len);
	memzero_explicit(input_hash, RM_PWD_HASH_LEN);
	kfree(stored_hash);
	kfree(input_hash);
	return cmp;
}

#endif
