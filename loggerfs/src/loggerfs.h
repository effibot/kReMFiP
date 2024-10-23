//
// Created by effi on 21/10/24.
//

#ifndef LOGGERFS_H
#define LOGGERFS_H
// ---------------------------------- Kernel ----------------------------------
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kernel.h>

#define MODNAME "LOGGERFS"
#ifdef __KERNEL__
#define INFO(fmt, ...)                                                                \
printk(KERN_INFO "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
##__VA_ARGS__);
#define WARNING(fmt, ...)                                                                \
printk(KERN_WARNING "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
##__VA_ARGS__);
#endif

// File System Constants
#define MAGIC 0x42424242
#define DEFAULT_BLOCK_SIZE 4096
#define SB_BLOCK_NUMBER 0
#define DEFAULT_FILE_INODE_BLOCK 1
#define FILENAME_MAXLEN 255
#define LOGFS_ROOT_INODE_NUMBER 10
#define LOGFS_FILE_INODE_NUMBER 1
#define LOGFS_INODES_BLOCK_NUMBER 1
#define UNIQUE_FILE_NAME "logfile"

// Inode definition
typedef struct __logfs_inode {
	mode_t mode;
	uint64_t inode_no;
	uint64_t data_block_number;
	union {
		uint64_t file_size;
		uint64_t dir_children_count;
	};
} lognode_t;

// Directory definition - how the directory data block is organized
typedef struct __logfs_dir_record {
	char filename[FILENAME_MAXLEN];
	uint64_t inode_no;
} logdir_t;

// Superblock definition
typedef struct __logfs_sb_info {
	uint64_t version;
	uint64_t magic;
	uint64_t block_size;
	uint64_t inodes_count;
	uint64_t free_blocks;
	// Padding to fit into a single block
	char padding[(4 * 1024) - (5 * sizeof(uint64_t))];
} logfs_sb_t;




#endif //LOGGERFS_H
