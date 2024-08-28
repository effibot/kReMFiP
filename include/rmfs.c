
/**
 * @file rmfs.c
 * @author Andrea Efficace (andrea.efficace1@gmail.com)
 * @brief Implementation of the reference monitor as a folder under /sys/kernel
 * We provide show/store operations and initialization functions for the reference monitor structure
 * @version 0.1
 * @date 2024-08-03
 *
 * @copyright Copyright (c) 2024
 *
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <crypto/hash.h>
#include <crypto/sha256_base.h>
#include <linux/memory.h>   // For secure memory zeroing

#include "rmfs.h"
#include "utils.h"

/*********************************
 * Internal functions prototypes *
 *********************************/
// internal state settings to make checks without leaking information in other files
int __set_state(rm_t *rm, rm_state_t state);
// internal password hashing function
static int __rm_hash_pwd(const char* pwd,  const u8 *pwd_salt, u8 *pwd_hash);
// internal password verification function
static bool __verify_pwd(const char* input_str);
static void __prompt_for_pwd(void);
// dedicated sysfs file for the password hash
static ssize_t module_pwd_hash_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

/*************************************************
 * Preliminary setup for the password management *
 *************************************************/
static char *module_pwd = NULL; // default value
static u8 pwd_salt[RM_PWD_SALT_LEN];
static u8 module_pwd_hash[RM_PWD_HASH_LEN];
static char* module_crypto_algo = "sha256"; // default value
module_param(module_pwd, charp, 0000);
MODULE_PARM_DESC(module_pwd, "The password for the reference monitor");

static struct kobj_attribute hash_pwd_attr = __ATTR_RO(module_pwd_hash);
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
	if (__rm_hash_pwd(module_pwd, pwd_salt, module_pwd_hash) != 0) {
		WARNING("Failed to hash the password");
		kfree(rm);
		return NULL;
	}

	// store the password hash in the dedicated sysfs file
	rm->kobj = kobject_create_and_add("module_pwd_hash", &THIS_MODULE->mkobj.kobj);
	if(rm->kobj == NULL) {
		WARNING("Failed to create the sysfs file for the password hash");
		kfree(rm);
		return NULL;
	}
	// create the file creating the group
	if(sysfs_create_group(rm->kobj, &attr_group)) {
		WARNING("Failed to create the sysfs group for the password hash");
		kobject_put(rm->kobj);
		kfree(rm);
		return NULL;
	}

#ifdef DEBUG
	// print the password hash
	printk(KERN_INFO "Password hash: %s\n", hex_to_str(module_pwd_hash, RM_PWD_HASH_LEN));
	// check if the password is correct
	if (__verify_pwd(module_pwd)) {
		printk(KERN_INFO "Password is correct\n");
	} else {
		printk(KERN_INFO "Password is incorrect\n");
	}
#endif
	INFO("Hash table initialized");
	return rm;
}

int set_state(rm_t *rm, const rm_state_t state) {
	// We need to check eUID to see if the user is root
	if (unlikely(!capable(CAP_SYS_ADMIN))) {
		INFO("User is not root");
		goto no_root;
	}
	// calling user has root privileges - asks for the reference monitor password
	if (unlikely(rm == NULL)) {
		INFO("Reference monitor is NULL");
		goto error;
	}

	// set the state
	if (__set_state(rm, state) != 0) {
		INFO("Failed to set the state");
		goto error;
	}
	return 0;
error:
	return -EINVAL;
no_root:
	return -EPERM;
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

int __set_state(rm_t *rm, const rm_state_t state) {
	//TODO - implement password check
	// assert that the reference monitor is not NULL
	if (unlikely(rm == NULL)) {
		INFO("Reference monitor is NULL");
		goto error;
	}
	// check if the state is valid
	if (!is_state_valid(state)) {
		INFO("Trying to set an invalid state - %s is given", state_to_str(state));
		goto error;
	}
#ifdef DEBUG
	INFO("Setting state to %s", state_to_str(state));
#endif
	// set the state
	rm->state = state;

	return 0;

	error:
		return -EINVAL;
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

static int __rm_hash_pwd(const char* pwd, const u8 *pwd_salt, u8 *pwd_hash) {

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
	memcpy(salted_pwd + RM_PWD_SALT_LEN, pwd, strlen(pwd));  // pointers arithmetic

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
	} else {
		printk(KERN_INFO "Password hash with salt computed successfully\n");
	}

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

static bool __verify_pwd(const char* input_str) {
	// be sure that the input string is not NULL
	if (IS_ERR_OR_NULL(input_str)) {
		WARNING("Input string is NULL");
		return false;
	}
	// we are not going to leak traces of the password in the kernel space
	// so we hash the input string and compare it with the stored hash takend from the sysfs
	u8 input_hash[RM_PWD_HASH_LEN];
	if (__rm_hash_pwd(input_str, pwd_salt, input_hash)) {
		WARNING("Failed to hash the input string");
		return false;
	}
	printk("%s\n", hex_to_str(input_hash, RM_PWD_HASH_LEN));
	// compare the hashes
	if (memcmp(input_hash, module_pwd_hash, RM_PWD_HASH_LEN) == 0)
		return true;
	return false;
}

/**
 * @brief Prompt the user for the password
 *
 * This function prompts the user for the password and hashes it.
 * The hashed password is stored in the dedicated sysfs file.
 */

static void __prompt_for_pwd(void) {

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
ssize_t module_pwd_hash_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	// just copy the password hash to the buffer as a null-terminated string
	return snprintf(buf, RM_PWD_HASH_LEN*2+1, "%s", hex_to_str(module_pwd_hash, RM_PWD_HASH_LEN));
}


