#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>


#include "loggerfs.h"
#include "operations.h"
#include <linux/buffer_head.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Efficace");
MODULE_DESCRIPTION("Logger File System");
MODULE_INFO(name, MODNAME);
MODULE_INFO(OS, "Linux");
MODULE_VERSION("1.0");

// Filesystem type
static struct file_system_type logfs_type = {
	.owner = THIS_MODULE,
	.name = "logfs",
	.mount = logfs_mount,
	.kill_sb = logfs_destroy_super,
};

static struct super_operations logfs_super_ops = {
};


static struct dentry_operations logfs_dentry_ops = {
};


// Destroy the Superblock
void logfs_destroy_super(struct super_block *sb) {
	kill_block_super(sb);
	INFO("LoggerFS superblock destroyed\n");
}

// Fill the superblock
int logfs_fill_super(struct super_block *sb, void *data, int silent) {
	struct timespec64 curr_time;

	//Unique identifier of the filesystem
	sb->s_magic = MAGIC;

	struct buffer_head *bh = sb_bread(sb, SB_BLOCK_NUMBER);
	if (!sb) {
		return -EIO;
	}
	const logfs_sb_t *sb_disk = (logfs_sb_t *)bh->b_data;
	const uint64_t magic = sb_disk->magic;
	brelse(bh);

	//check on the expected magic number
	if(magic != sb->s_magic){
		return -EBADF;
	}

	sb->s_fs_info = NULL; //FS specific data (the magic number) already reported into the generic superblock
	sb->s_op = &logfs_super_ops;//set our own operations


	struct inode *root_inode =
		iget_locked(sb, LOGFS_ROOT_INODE_NUMBER); //get a root inode from cache
	if (!root_inode){
		return -ENOMEM;
	}

    inode_init_owner(root_inode, NULL, S_IFDIR);//set the root user as owner of the FS root
	root_inode->i_sb = sb;
	root_inode->i_op = &logfs_inode_ops;//set our inode operations
	root_inode->i_fop = &logfs_dir_operations;//set our file operations
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

	sb->s_root->d_op = &logfs_dentry_ops;//set our dentry operations

	//unlock the inode to make it usable
	unlock_new_inode(root_inode);

	return 0;
}

// Mount the filesystem
struct dentry *logfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data) {
	struct dentry *ret = mount_bdev(fs_type, flags, dev_name, data, logfs_fill_super);
	if (IS_ERR(ret)) {
		WARNING("LoggerFS mounting failed\n");
	} else {
		INFO("LoggerFS mounted\n");
	}
	return ret;
}
// Mutex for operations
DEFINE_MUTEX(logfs_mutex);

// Init the module
static int __init loggerfs_init(void) {
	const int ret = register_filesystem(&logfs_type);
	if (ret == 0) {
		INFO("LoggerFS module loaded\n");
	} else {
		WARNING("LoggerFS module failed to load\n");
	}
	return ret;
}

// Exit the module
static void __exit loggerfs_exit(void) {
	const int ret = unregister_filesystem(&logfs_type);
	if (ret == 0) {
		INFO("LoggerFS module unloaded\n");
	} else {
		WARNING("LoggerFS module failed to unload\n");
	}
}

// Link the init and exit functions
module_init(loggerfs_init);
module_exit(loggerfs_exit);
