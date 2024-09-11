
/**
 * @file rm.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Implementation of the reference monitor as a folder under /sys/kernel
 * We provide show/store operations and initialization functions for the reference monitor structure
 * @version 0.1
 * @date 2024-08-03
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "rm.h"
#include "misc.h"
#include "state.h"
#include <crypto/hash.h>
#include <crypto/sha256_base.h>
#include <linux/crypto.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/memory.h> // For secure memory zeroing
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/vfs.h>
#include <linux/workqueue.h>

/*********************************
 * Internal functions prototypes *
 *********************************/
// internal password hashing function
static int __rm_hash_pwd(const char *pwd, const u8 *pwd_salt, u8 *pwd_hash);
// internal password verification function
//static bool __verify_pwd(const char *input_str);
// dedicated sysfs file for the password hash
static ssize_t rm_pwd_hash_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

/*************************************************
 * Preliminary setup for the password management *
 *************************************************/
static char *module_pwd = NULL; // default value
static u8 pwd_salt[RM_PWD_SALT_LEN];
static u8 rm_pwd_hash[RM_PWD_HASH_LEN];
static char *module_crypto_algo = "sha256"; // default value
module_param(module_pwd, charp, 0000);
MODULE_PARM_DESC(module_pwd, "The password for the reference monitor");

static struct kobj_attribute hash_pwd_attr = __ATTR_RO(rm_pwd_hash);
static struct attribute *attrs[] = {
	&hash_pwd_attr.attr,
	NULL,
};
static struct attribute_group attr_group = {
	.attrs = attrs,
};

//********************************************************************************
/**
 * @brief Initialize the reference monitor
 *
 * This function initializes the reference monitor structure.
 * It allocates memory for the reference monitor, sets the default values,
 * and initializes the hash table.
 *
 * @return rm_t* A pointer to the reference monitor structure
 */

rm_t *rm_init(void) {
	// Allocate memory for the reference monitor
	rm_t *rm = kzalloc(sizeof(rm), GFP_KERNEL);
	if (unlikely(rm == NULL)) {
		INFO("Failed to allocate memory for the reference monitor");
		return NULL;
	}
	// Set the default values
	rm->name = RMFS_DEFAULT_NAME;
	rm->state = RM_INIT_STATE;
	rm->id = rnd_id();
	// Initialize the hash table and be sure that all goes well
	rm->ht = ht_create(HT_SIZE);
	if (unlikely(rm->ht == NULL)) {
		WARNING("Failed to initialize the hash table");
		kfree(rm);
		return NULL;
	}

	// initialize the salt
	get_random_bytes(pwd_salt, RM_PWD_SALT_LEN);
	// hash the password with the salt
	if (__rm_hash_pwd(module_pwd, pwd_salt, rm_pwd_hash) != 0) {
		WARNING("Failed to hash the password");
		kfree(rm);
		return NULL;
	}

	// store the password hash in the dedicated sysfs file
	// we crate a subfolder under /sys/module/kremfip
	rm->kobj = kobject_create_and_add("rm_pwd_hash", &THIS_MODULE->mkobj.kobj);
	if (rm->kobj == NULL) {
		WARNING("Failed to create the sysfs file for the password hash");
		kfree(rm);
		return NULL;
	}
	// create the file creating the group
	if (sysfs_create_group(rm->kobj, &attr_group)) {
		WARNING("Failed to create the sysfs group for the password hash");
		kobject_put(rm->kobj);
		kfree(rm);
		return NULL;
	}
	// check if the password hash is stored correctly
	if(!verify_pwd(module_pwd)) {
		WARNING("Failed to verify the password hash");
		kfree(rm);
		return NULL;
	}
	INFO("Hash table initialized");
	return rm;
}
/**
 * @brief Set the state of the reference monitor to a VALID state.
 * Since this is the setter function, we avoid to make checks here,
 * as they should be done in the caller function.
 * @param rm The reference monitor structure
 * @param state The new state of the reference monitor
 * @return int 0 if the state is set successfully, an error code otherwise
 */
int set_state(rm_t *rm, const rm_state_t state) {
	// safety checks
	if(unlikely(rm == NULL)) {
		WARNING("Reference monitor is NULL");
		return -EINVAL;
	}

	// set the state
#ifdef DEBUG
	INFO("Setting the state to %s\n", state_to_str(state));
#endif
	rm->state = state;
	return 0;
}

rm_state_t get_state(const rm_t *rm) {
	// assert that the reference monitor is not NULL
	if (rm == NULL) {
		INFO("Reference monitor is NULL");
		return -EINVAL;
	}
	// return the state
	return rm->state;
}

void rm_free(const rm_t *rm) {
	// assert that the reference monitor is not NULL
	if (rm == NULL) {
		INFO("Reference monitor is NULL");
		return;
	}
	// free the hash table
	ht_destroy(rm->ht);
	// remove the sysfs file
	sysfs_remove_file(rm->kobj, &hash_pwd_attr.attr);
	kobject_put(rm->kobj);
	// free the reference monitor
	kfree(rm);
}

/*************************************
 * Internal function implementations *
 *************************************/

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

static int __rm_hash_pwd(const char *pwd, const u8 *pwd_salt, u8 *pwd_hash) {
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
	struct crypto_shash *tfm = crypto_alloc_shash(module_crypto_algo, 0, 0);
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

bool verify_pwd(const char *input_str) {
	// Ensure the input string is not NULL
	INFO("Verifying the password");
	if (IS_ERR_OR_NULL(input_str)) {
		WARNING("Input string is NULL");
		return false;
	}
	INFO("Input string is not NULL, performing hash");
	// Hash the input string
	u8 *input_hash = kzalloc(RM_PWD_HASH_LEN*sizeof(u8), GFP_KERNEL);
	if (__rm_hash_pwd(input_str, pwd_salt, input_hash)) {
		WARNING("Failed to hash the input string");
		return false;
	}
	INFO("Hash computed successfully");
	// Retrieve the stored hash from the sysfs
	struct file *f = filp_open("/sys/module/kremfip/rm_pwd_hash/rm_pwd_hash", O_RDONLY, 0);
	if (IS_ERR(f)) {
		WARNING("Failed to open the sysfs file");
		return false;
	}
	INFO("Sysfs file opened successfully");
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
	INFO("Stored hash read successfully");
	// Compare the hashes
	INFO("Comparing hashes: %s vs %s", hex_to_str(input_hash, RM_PWD_HASH_LEN), stored_hash);
	const bool cmp =
		memcmp(hex_to_str(input_hash, RM_PWD_HASH_LEN), stored_hash, RM_PWD_HASH_LEN) == 0;
	INFO("Hashes compared successfully");
	// Clean up the stored hash
	memzero_explicit(stored_hash, stored_hash_len);
	INFO("memzeroed stored hash");
	memzero_explicit(input_hash, RM_PWD_HASH_LEN);
	INFO("memzeroed input hash");
	kfree(stored_hash);
	INFO("clean up mem");
	kfree(input_hash);
	INFO("clean up mem");
	return cmp;
}

/**
 * @brief Show the password hash
 *
 * This function shows the password hash in the sysfs file.
 *
 * @param kobj The kobject
 * @param attr The kobject attribute
 * @param buf The buffer to store the password hash
 * @return ssize_t The number of bytes written
 */
ssize_t rm_pwd_hash_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	// just copy the password hash to the buffer as a null-terminated string
	return snprintf(buf, RM_PWD_HASH_LEN * 2 + 1, "%s", hex_to_str(rm_pwd_hash, RM_PWD_HASH_LEN));
}
