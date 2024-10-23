//
// Created by effi on 22/10/24.
//

#ifndef OPERATIONS_H
#define OPERATIONS_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>

// Superblock operations

// Fill the superblock
int logfs_fill_super(struct super_block *sb, void *data, int silent);
// Mount the superblock
struct dentry *logfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data);
// Destroy the superblock
void logfs_destroy_super(struct super_block *sb);

// File and Dir Operations handlers
struct dentry *logfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags);
ssize_t logfs_read(struct file * filp, char __user * buf, size_t len, loff_t * off);
ssize_t logfs_write(struct file * filp, char __user * buf, size_t len, loff_t * off);
ssize_t logfs_write_iter(struct kiocb *iocb, struct iov_iter *from);
int logfs_iterate(struct file *file, struct dir_context* ctx);

extern const struct inode_operations logfs_inode_ops;
extern const struct file_operations logfs_file_operations;
extern const struct file_operations logfs_dir_operations;

#endif //OPERATIONS_H
