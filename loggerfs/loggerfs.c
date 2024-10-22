//
// Created by effi on 21/10/24.
//

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>


#include "loggerfs.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
MODULE_DESCRIPTION("Logger File System");
MODULE_INFO(name, MODNAME);
MODULE_INFO(OS, "Linux");
MODULE_VERSION("1.0");


// Destroy the Superblock
static void loggerfs_destroy_super(struct super_block *sb) {
	kill_block_super(sb);
	INFO("LoggerFS superblock destroyed\n");
	return;
}

// Fill the superblock
static int loggerfs_fill_super(struct super_block *sb, void *data, int silent) {
	struct inode *root_inode;
	struct buffer_head *bh;
	struct onefilefs_sb_info *sb_disk;
	struct timespec64 curr_time;
	uint64_t magic;


	//Unique identifier of the filesystem
	sb->s_magic = MAGIC;

	bh = sb_bread(sb, SB_BLOCK_NUMBER);
	if(!sb){
		return -EIO;
	}
	sb_disk = (struct onefilefs_sb_info *)bh->b_data;
	magic = sb_disk->magic;
	brelse(bh);

	//check on the expected magic number
	if(magic != sb->s_magic){
		return -EBADF;
	}

	sb->s_fs_info = NULL; //FS specific data (the magic number) already reported into the generic superblock
	sb->s_op = &singlefilefs_super_ops;//set our own operations


	root_inode = iget_locked(sb, SINGLEFILEFS_ROOT_INODE_NUMBER);//get a root inode from cache
	if (!root_inode){
		return -ENOMEM;
	}

	inode_init_owner(current->cred->user_ns,root_inode, NULL, S_IFDIR);//set the root user as owner of the FS root
	root_inode->i_sb = sb;
	root_inode->i_op = &onefilefs_inode_ops;//set our inode operations
	root_inode->i_fop = &onefilefs_dir_operations;//set our file operations
	//update access permission
	root_inode->i_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;

	//baseline alignment of the FS timestamp to the current time
	ktime_get_real_ts64(&curr_time);
	root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime = curr_time;

	// no inode from device is needed - the root of our file system is an in memory object
	root_inode->i_private = NULL;

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		return -ENOMEM;

	sb->s_root->d_op = &singlefilefs_dentry_ops;//set our dentry operations

	//unlock the inode to make it usable
	unlock_new_inode(root_inode);

	return 0;
}

// Mount the filesystem
static struct dentry *loggerfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data) {
	struct dentry *ret;
	ret = mount_bdev(fs_type, flags, dev_name, data, loggerfs_fill_super);
	if (IS_ERR(ret)) {
		WARNING("LoggerFS mounting failed\n");
	} else {
		INFO("LoggerFS mounted\n");
	}
	return ret;
}

// Filesystem type
static struct file_system_type loggerfs_type = {
	.owner = THIS_MODULE,
	.name = "loggerfs",
	.mount = loggerfs_mount,
	.kill_sb = loggerfs_destroy_super,
};

// Init the module
static int __init loggerfs_init(void) {
	int ret;
	ret = register_filesystem(&loggerfs_type);
	if (ret == 0) {
		INFO("LoggerFS module loaded\n");
	} else {
		WARNING("LoggerFS module failed to load\n");
	}
	return ret;
}

// Exit the module
static void __exit loggerfs_exit(void) {
	int ret;
	ret = unregister_filesystem(&loggerfs_type);
	if (ret == 0) {
		INFO("LoggerFS module unloaded\n");
	} else {
		WARNING("LoggerFS module failed to unload\n");
	}
}

// Link the init and exit functions
module_init(loggerfs_init);
module_exit(loggerfs_exit);
