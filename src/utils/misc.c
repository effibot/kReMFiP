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
	if (strlen((char *)hex) == 0 || len == 0 || hex == NULL) {
		return NULL;
	}
	// allocate the string -- 2 hex characters for each byte
	char *str = kzalloc(len * 2 + 1, GFP_KERNEL);
	if (str == NULL) {
		return NULL;
	}
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
	unsigned long ret;
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
		WARNING("Password is not set");
		return -EINVAL;
	}
	// concatenate the password and the salt
	const size_t salted_len = strlen(pwd) + RM_PWD_SALT_LEN;
	u8 *salted_pwd = kzalloc(salted_len, GFP_KERNEL);
	if (unlikely(salted_pwd == NULL)) {
		WARNING("Failed to allocate memory for the salted password");
		return -ENOMEM;
	}
	int ret = 0;
	// Add the salt at the head because is proven to be more secure
	memcpy(salted_pwd, pwd_salt, RM_PWD_SALT_LEN);
	// Copy the password after the salt, the + is for pointer arithmetic
	memcpy(salted_pwd + RM_PWD_SALT_LEN, pwd, strlen(pwd));

	// allocate memory for the hash - we use the SHA256 algorithm because yes
	struct crypto_shash *tfm = crypto_alloc_shash(RM_CRYPTO_ALGO, 0, 0);
	if (IS_ERR(tfm)) {
		WARNING("Failed to allocate crypto shash");
		ret = (int)PTR_ERR(tfm);
		goto hash_init_out;
	}

	// Allocate descriptor for hash (synchronous hash)
	struct shash_desc *desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		WARNING("Failed to allocate hash descriptor\n");
		ret = -ENOMEM;
		goto desc_out;
	}
	// Initialize the descriptor
	desc->tfm = tfm;

	// Initialize the hash descriptor
	ret = crypto_shash_init(desc);
	if (ret) {
		WARNING("Hash initialization failed\n");
		goto out;
	}

	// Hash the salted password
	ret = crypto_shash_update(desc, salted_pwd, salted_len);
	if (ret) {
		WARNING("Hash update failed\n");
		goto out;
	}

	// Finalize the hash
	ret = crypto_shash_final(desc, pwd_hash);
	if (ret) {
		WARNING("Hash finalization failed\n");
	}
#ifdef DEBUG
	INFO("Password hash with salt computed successfully\n");
#endif

// free the memory - we don't want to leak traces of the password

out:
	memzero_explicit(desc, sizeof(*desc));
	kfree(desc);
desc_out:
	crypto_free_shash(tfm);
hash_init_out:
	memzero_explicit(salted_pwd, salted_len);
	kfree(salted_pwd);
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
	// Checks if the length of the inserted password is feasible
	if (strlen(input_str) < RM_PWD_MIN_LEN || strlen(input_str) > RM_PWD_MAX_LEN) {
		WARNING("Password length is not feasible");
		return false;
	}
	bool cmp = false;
	// Hash the input string
	u8 *input_hash = kzalloc(RM_PWD_HASH_LEN*sizeof(u8), GFP_KERNEL);
	if (IS_ERR_OR_NULL(input_hash)) {
		WARNING("Failed to allocate memory for the input hash");
		return false;
	}
	if (hash_pwd(input_str, pwd_salt, input_hash)) {
		WARNING("Failed to hash the input string");
		goto input_out;
	}
	// Retrieve the stored hash from the sysfs
	struct file *f = filp_open(RM_PWD_HASH_PATH, O_RDONLY, 0);
	if (IS_ERR(f)) {
		WARNING("Failed to open the sysfs file");
		goto input_out;
	}
	// Read the stored hash from the sysfs
	char *stored_hash;
	stored_hash = kzalloc(RM_STR_HASH_LEN*sizeof(char), GFP_KERNEL);
	if (IS_ERR_OR_NULL(stored_hash)) {
		WARNING("Failed to allocate memory for the stored hash");
		filp_close(f, NULL);
		goto stored_out;
	}
	const ssize_t bytes_read = kernel_read(f, stored_hash, RM_STR_HASH_LEN, &f->f_pos);
	// we have read the hash, close the fd whatever happens
	filp_close(f, NULL);
	if (bytes_read < 0) {
		WARNING("Failed to read the stored hash from the sysfs file");
		goto stored_out;
	}
	// Compare the hashes
	cmp = memcmp(hex_to_str(input_hash, RM_PWD_HASH_LEN), stored_hash, RM_PWD_HASH_LEN) == 0;
#ifdef DEBUG
	INFO("Hashes compared successfully");
#endif
	// Clean up the stored hash
stored_out:
	memzero_explicit(stored_hash, RM_STR_HASH_LEN);
	kfree(stored_hash);
input_out:
	memzero_explicit(input_hash, RM_PWD_HASH_LEN);
	kfree(input_hash);
	return cmp;
}

/**
 * @brief Elevate the privileges of the current process to root.
 * This function elevates the privileges of the current process to root, if it's not already root.
 * @remark REMEMBER TO STORE THE PREVIOUS UIDs AND GIDs TO RESTORE THEM LATER.
 * THIS MUST ALWAYS BE SUCCEEDED BY reset_privileges TO RESTORE THE PRIVILEGES.
 * @return int the old EUID of the thread on success, an error code otherwise.
 */
inline int elevate_privileges(void) {
	// Check if the user is already root
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
		INFO("Already running as root\n");
		// Return 0 to indicate that the user is already root
		return 0;
	}
	// The user is not root, so we need to escalate the privileges
	INFO("Getting creds");
	struct cred *creds;
	creds = prepare_creds();
	if (IS_ERR(creds)) {
		WARNING("Failed to prepare the credentials\n");
		return (int)PTR_ERR(creds);

	}
	INFO("Setting the EUID to root");
	// Save the old EUID
	const kuid_t old_euid = current_euid();
	// Set the EUID to root
	creds->euid = GLOBAL_ROOT_UID;
	// Commit the new credentials - commit_creds returns 0 on success
	if(commit_creds(creds)) {
		WARNING("Failed to set new EUID\n");
		return -EPERM;
	}
	INFO("commit failed");
	// Return the old EUID
	return (int)old_euid.val;
}

/**
 * @brief Reset the privileges of the current process.
 * This function resets the privileges of the current process to the original ones.
 * @return 0 on success, error code otherwise
 */
inline int reset_privileges(uid_t old_euid) {
	// Check if the user is already root
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
		INFO("Already running as root\n");
		return 0;
	}
	// The user is not root, so we need to reset the privileges
	struct cred *creds;
	creds = prepare_creds();
	if (IS_ERR(creds)) {
		WARNING("Failed to prepare the credentials\n");
		return (int)PTR_ERR(creds);
	}
	// Set the EUID to the old value
	creds->euid = make_kuid(current_user_ns(), old_euid);
	// Commit the new credentials - commit_creds returns 0 on success
	if(commit_creds(creds)) {
		WARNING("Failed to set new EUID\n");
		return -EPERM;
	}
	return 0;
}



#endif
