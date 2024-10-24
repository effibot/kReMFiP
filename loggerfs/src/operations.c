#include "operations.h"
#include "loggerfs.h"
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>

#include <linux/uio.h>

extern struct mutex logfs_mutex;
uint64_t file_size;

ssize_t logfs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

	struct buffer_head *bh = NULL;
	const struct inode *the_inode = filp->f_inode;
	const uint64_t file_size = the_inode->i_size;
	//index of the block to be read from device

	printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MODNAME, len, *off, file_size);

	//this operation is not synchronized
	//*off can be changed concurrently
	//add synchronization if you need it for any reason
	mutex_lock(&logfs_mutex);
	//check that *off is within boundaries
	if (*off >= file_size) {
		mutex_unlock(&logfs_mutex);
		return 0;
	}
	if (*off + len > file_size)
		len = file_size - *off;

	//determine the block level offset for the operation
	const loff_t offset = *off % DEFAULT_BLOCK_SIZE;
	//just read stuff in a single block - residuals will be managed at the applicatin level
	if (offset + len > DEFAULT_BLOCK_SIZE)
		len = DEFAULT_BLOCK_SIZE - offset;

	//compute the actual index of the the block to be read from device
	const long long block_to_read = *off / DEFAULT_BLOCK_SIZE +
						2; //the value 2 accounts for superblock and file-inode on device

	printk("%s: read operation must access block %lld of the device",MODNAME, block_to_read);

	bh = sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
	if (!bh) {
		mutex_unlock(&logfs_mutex);
		return -EIO;
	}
	const size_t ret = copy_to_user(buf, bh->b_data + offset, len);
	*off += (loff_t)(len - ret);
	brelse(bh);
	mutex_unlock(&logfs_mutex);
	return (loff_t)(len - ret);

}

struct dentry *logfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {
	struct super_block *sb = parent_inode->i_sb;
	struct buffer_head *bh = NULL;
	struct inode *the_inode = NULL;

	printk("%s: running the lookup inode-function for name %s",MODNAME,(const char*)child_dentry->d_name.name);

	if(!strcmp((const char*)child_dentry->d_name.name, UNIQUE_FILE_NAME)) {
		//get a locked inode from the cache
		the_inode = iget_locked(sb, 1);
		if (!the_inode)
			return ERR_PTR(-ENOMEM);

		//already cached inode - simply return successfully
		if(!(the_inode->i_state & I_NEW)){
			return child_dentry;
		}


		//this work is done if the inode was not already cached
		inode_init_owner(the_inode, NULL, S_IFREG );
		the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
		the_inode->i_fop = &logfs_file_operations;
		the_inode->i_op = &logfs_inode_ops;

		//just one link for this file
		set_nlink(the_inode,1);

		//now we retrieve the file size via the FS specific inode, putting it into the generic inode
		bh = sb_bread(sb, LOGFS_INODES_BLOCK_NUMBER);
		if (!bh) {
			iput(the_inode);
			return ERR_PTR(-EIO);
		}
		const lognode_t *FS_specific_inode = (lognode_t *)bh->b_data;
		the_inode->i_size = (loff_t)FS_specific_inode->file_size;
		brelse(bh);

		d_add(child_dentry, the_inode);
		dget(child_dentry);

		//unlock the inode to make it usable
		unlock_new_inode(the_inode);

		return child_dentry;
	}

	return NULL;

}

//this iterate function just returns 3 entries: . and .. and then the name of the unique file of the file system
int logfs_iterate(struct file *file, struct dir_context* ctx) {

	//	printk("%s: we are inside readdir with ctx->pos set to %lld", MOD_NAME, ctx->pos);

	if(ctx->pos >= (2 + 1)) return 0;//we cannot return more than . and .. and the unique file entry

	if (ctx->pos == 0){
		//   		printk("%s: we are inside readdir with ctx->pos set to %lld", MOD_NAME, ctx->pos);
		if (!dir_emit(ctx, ".", FILENAME_MAXLEN, LOGFS_ROOT_INODE_NUMBER, DT_UNKNOWN)) {
			return 0;
		}
		ctx->pos++;
	}

	if (ctx->pos == 1){
		//  		printk("%s: we are inside readdir with ctx->pos set to %lld", MOD_NAME, ctx->pos);
		//here the inode number does not care
		if (!dir_emit(ctx, "..", FILENAME_MAXLEN, 1, DT_UNKNOWN)) {
			return 0;
		}
		ctx->pos++;
	}
	if (ctx->pos == 2){
		// 		printk("%s: we are inside readdir with ctx->pos set to %lld", MOD_NAME, ctx->pos);
		if (!dir_emit(ctx, UNIQUE_FILE_NAME, FILENAME_MAXLEN, LOGFS_FILE_INODE_NUMBER,
					  DT_UNKNOWN)) {
			return 0;
		}
		ctx->pos++;
	}

	return 0;

}

ssize_t logfs_write(struct file * filp, char __user * buf, size_t len, loff_t * off) {
	//index of the block to be read from device
	struct buffer_head *bh = NULL;
	struct inode * the_inode = filp->f_inode;
	uint64_t file_size = the_inode->i_size;

	// perform locking as stated in the kernel documentation
	mutex_lock(&logfs_mutex);
	i_size_write(the_inode, (loff_t)file_size);
	mutex_unlock(&logfs_mutex);

	*off = i_size_read(the_inode); //writing in append mode ONLY

	printk("%s: write operation called with len %ld - and offset %lld (the current file size is %lld)", MODNAME, len, *off, file_size);

	//determine the block level offset for the operation
	const loff_t offset = *off % DEFAULT_BLOCK_SIZE;
	//just read stuff in a single block - residuals will be managed at the application level
	if (offset + len > DEFAULT_BLOCK_SIZE)
		len = DEFAULT_BLOCK_SIZE - offset;

	//compute the actual index of the the block to be read from device
	const long long block_to_read = *off / DEFAULT_BLOCK_SIZE +
						2; //the value 2 accounts for superblock and file-inode on device

	printk("%s: write operation must access block %lld of the device",MODNAME, block_to_read);

	bh = sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
	if (!bh) {
		return -EIO;
	}
	const size_t ret = copy_from_user(bh->b_data + offset, buf, len);
	sync_dirty_buffer(bh); //write immediately on disk
	*off += (loff_t)(len - ret);
	//updating global variable (O_APPEND in open() updates the file length to 0 so we need to keep original lenght)
	file_size = *off;

	// perform locking as stated in the kernel documentation
	mutex_lock(&logfs_mutex);
	i_size_write(the_inode, *off);
	mutex_unlock(&logfs_mutex);
	brelse(bh);

	return (loff_t)(len - ret);

}

ssize_t logfs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
	const struct file *filp = iocb->ki_filp;
	const char *buf= from->kvec->iov_base;
	size_t len = from->kvec->iov_len;

	//index of the block to be read from device
	struct buffer_head *bh = NULL;
	struct inode * the_inode = filp->f_inode;
	mutex_lock(&logfs_mutex);
	i_size_write(the_inode, (loff_t)file_size);
	mutex_unlock(&logfs_mutex);

	loff_t off = i_size_read(the_inode); //writing in append mode ONLY

	printk("%s: write operation called with len %ld - and offset %lld (the current file size is %lld)",MODNAME, len, off, file_size);

	//determine the block level offset for the operation
	const loff_t offset = off % DEFAULT_BLOCK_SIZE;
	//just read stuff in a single block - residuals will be managed at the applicatin level
	if (offset + len > DEFAULT_BLOCK_SIZE)
		len = DEFAULT_BLOCK_SIZE - offset;

	//compute the actual index of the the block to be read from device
	const long long block_to_read =
		off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device

	printk("%s: write operation must access block %lld of the device",MODNAME, block_to_read);

	bh = sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
	if(!bh){
		return -EIO;
	}
	memcpy(bh->b_data + offset, buf, len);
	sync_dirty_buffer(bh); //write immediately on disk
	off += (loff_t)len;
	//updating global variable (O_APPEND in open() updates the file length to 0 so we need to keep original lenght)
	file_size = off;
	i_size_write(the_inode, off);
	brelse(bh);

	return (ssize_t)len;
}


//look up goes in the inode operations
const struct inode_operations logfs_inode_ops = {
	.lookup = logfs_lookup,
};

//read goes in the file operations
const struct file_operations logfs_file_operations = {
	.owner = THIS_MODULE,
	.llseek = default_llseek,
	.read = logfs_read,
	//.write = logfs_write
	.write_iter = logfs_write_iter,
};

//add the iterate function in the dir operations
const struct file_operations logfs_dir_operations = {
	.owner = THIS_MODULE,
	.iterate = logfs_iterate,
};
