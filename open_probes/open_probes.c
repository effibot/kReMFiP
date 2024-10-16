
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>

#define MODNAME "open_probes"

#define INVALID_PATHS_NUM 26
static const char *invalid_paths[INVALID_PATHS_NUM] = {
	"/bin", "/boot", "/cdrom", "/dev", "/etc", "/lib", "/lib64", "/mnt", "/opt", "/proc",
	"/root", "/run", "/sbin", "/snap", "/srv", "/swapfile", "/sys", "/usr", "/var", "/tmp",
	"/home/effi/.cache","/home/effi/.java", "/home/effi/.Xauthority", ".git",
	"/home/effi/.local", "/home/effi/.config"


};
#define INFO(fmt, ...)                                                                \
	printk(KERN_INFO "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
	       ## __VA_ARGS__);
#define WARNING(fmt, ...)                                                                \
	printk(KERN_WARNING "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
	       ## __VA_ARGS__);
// Declaration of the is_protected function (you'll need to implement it)
extern int is_protected(const char *path){
	if(strcmp(path,"/home/effi/file0.txt") == 0) {
		pr_info("%s is protected", path);
		return 1;
	}
	if(strcmp(path,"/home/effi/file1.txt") == 0) {
		pr_info("%s is protected", path);
		return 1;
	}
	if(strcmp(path,"/home/effi/Downloads") == 0) {
		pr_info("%s is protected", path);
		return 1;
	}
	if(strcmp(path, "/home/effi/testdir") == 0) {
		pr_info("%s is protected", path);
		return 1;
	}
	return 0;
}
bool is_valid_path(const char *path) {
	if (unlikely(path == NULL)) {
#ifdef DEBUG
		INFO("Passing null path (%p)\n", path);
#endif
		return false;
	}
	// if the path belongs to some system mount point, return false
	for (int i = 0; i < INVALID_PATHS_NUM; i++) {
		if (str_has_prefix(path, invalid_paths[i]) > 0) {
			return false;
		}
	}

	return true;
}

// Struct representing flags passed to open syscall
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};



char *get_cwd(void){

	struct path abs_path;
	char *buf, *full_path;

	buf = kmalloc(PATH_MAX,GFP_KERNEL);
	if(buf == NULL) return "";

	get_fs_pwd(current->fs, &abs_path);

	full_path = dentry_path_raw(abs_path.dentry, buf, PATH_MAX);
	full_path = krealloc(full_path, strlen(full_path) + 1, GFP_KERNEL);
	if(IS_ERR(full_path)) {
		kfree(buf);
		return "";
	}
	kfree(buf);
	return full_path;

}

int get_abs_path(const char *path, char *abs_path) {
	if (unlikely(path == NULL)) {
		WARNING("Path is NULL\n");
		return -EINVAL;
	}

	struct path path_struct;
	int ret = kern_path(path, LOOKUP_FOLLOW, &path_struct);
	if (ret) {
#ifdef DEBUG
		WARNING("Unable to resolve the path, fallback\n");
#endif
		goto not_found;
	}

	char *tmp_path = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out_path_put;
	}
	char *resolved_path = d_path(&path_struct, tmp_path, PATH_MAX);
	if (IS_ERR(resolved_path)) {
		ret = -ENOENT;
		goto out_free;
	}
	// terminate the string, just to be sure
	*(resolved_path + strlen(resolved_path)) = '\0';
	// resolved_path = krealloc(resolved_path, strlen(resolved_path) + 1, GFP_KERNEL);
	ret = (int)strscpy(abs_path, resolved_path, PATH_MAX);
	// kfree(resolved_path);
	if (ret <= 0) {
		WARNING("Unable to copy the resolved path\n");
		ret = -ENOMEM;
	}
	ret = ret <= 0 ? ret : 0;
out_free:
	kfree(tmp_path);
out_path_put:
	path_put(&path_struct);
not_found:
	return ret;
}

int get_dir_path(const char *path, char *dir_path) {
	int ret = 0;
	char *tmp_path = NULL;

	if (unlikely(path == NULL)) {
		WARNING("Path is NULL\n");
		ret = -EINVAL;
		goto out;
	}

	// Copy the path to a temporary buffer
	tmp_path = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if (unlikely(tmp_path == NULL)) {
		WARNING("Unable to allocate memory for the path\n");
		ret = -ENOMEM;
		goto out;
	}
	ret = (int)strscpy(tmp_path, path, PATH_MAX);
	if (ret <= 0) {
		WARNING("Unable to copy the path\n");
		ret = -ENOMEM;
		goto out_free;
	}
	// reduce memory overhead by reallocating the buffer
	tmp_path = krealloc(tmp_path, strlen(tmp_path) + 1, GFP_KERNEL);
	/* Find the last occurrence of the directory separator:
	 * We could have three cases:
	 * 1. path = "/path/to/dir/file" ->  we need to find the last occurrence of the separator
	 * 2. path = "dir/file" -> we need to find the first occurrence of the separator
	 * 3. path = "file" -> we need to return the current directory
	 */
	const char *last_sep = strrchr(tmp_path, '/');

	if (last_sep) {
		// calculate the length +1 so that the copy include the null-terminator
		const size_t len = last_sep - tmp_path +1;
		// null-terminate the temp path to the last sep
		*(tmp_path + len) = '\0';
		// copy
		ret = (int)strscpy(dir_path, tmp_path, PATH_MAX);
		if (ret <= 0) {
			WARNING("Unable to copy the path\n");
			goto out_free;
		}
	} else {
		// If no separator is found, return the current directory
		const char * cwd = get_cwd();
		ret = (int)strscpy(dir_path, cwd, PATH_MAX);
		if (ret <= 0) {
			WARNING("Unable to copy the path\n");
			goto out_free;
		}
	}
	ret = 0;
out_free:
	kfree(tmp_path);
out:
	return ret;
}
//
//
//// Pre-handler for the kprobe
//static int pre_do_filp_open(struct kprobe *p, struct pt_regs *regs) {
//	const char *pathname = NULL;
//	const __user char *u_pathname = NULL;
//	// Extract the function arguments from the registers based on the x86_64 ABI
//
//	struct filename *name =
//		(struct filename *)regs->si; // 2nd argument: filename (struct filename pointer)
//	struct open_flags *open_flags =
//		(struct open_flags *)regs->dx; // 3rd argument: open_flags (struct open_flags pointer)
//
//	int flags = open_flags->open_flag; // Open flags
//	// Only proceed if the file is opened for writing or creating
//	if (!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL)))
//		return 0;
//
//	// Get the file path from the filename struct
//	pathname = name->name;
//	u_pathname = name->uptr;
//	// If pathname is NULL, there's nothing to check, skip
//	if (!pathname) {
//		return 0;
//	}
//
//	// Check if the path is valid and should be monitored
//	if (!is_valid_path(pathname)) {
//		return 0; // Skip if the path is not valid
//	}
//	int _dir = 0, _file = 0;
//	int dfd = (int)regs->di; // 1st argument: directory file descriptor
//
//#ifdef DEBUG
//	INFO("Probing do_filp_open with dfd %d and (flags, mode)=(%d, %d) for path %s\n", dfd,
//		 open_flags->open_flag, open_flags->mode, pathname);
//#endif
//	// Get the absolute path of the file its parent directory
//	char *path_buf = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
//	if (unlikely(path_buf == NULL)) {
//		WARNING("Failed to allocate memory for the path buffer\n");
//		return 0;
//	}
//	char *parent_buf = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
//	if (unlikely(parent_buf == NULL)) {
//		WARNING("Failed to allocate memory for the parent buffer\n");
//		kfree(path_buf);
//		return 0;
//	}
//	int err_abs = 0;
//
//
//
//}
//
//
//
//
static const char *reg_internal_file = "int_file.txt";
const char *internal_dir = "int_dir";
const char *reg_external_file = "/home/effi/file0.txt";
const char *external_dir = "/home/effi/file0.txt";
const char *re_external_dir_file = "/home/effi/test_dir/test";

static const char *test_paths[6] = {
	"int_file.txt", "int_dir", "int_dir/int_int_file",
	"/home/effi/file0.txt", "/home/effi/file0.txt",
	"/home/effi/test_dir/test"
};
static int pre_do_filp_open(struct kprobe *kp, struct pt_regs *regs) {
	struct filename *name =
		(struct filename *)regs->si; // 2nd argument: filename (struct filename pointer)
	struct open_flags *open_flags =
		(struct open_flags *)regs->dx; // 3rd argument: open_flags (struct open_flags pointer)

	int flags = open_flags->open_flag; // Open flags
	if (!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL))) return 0;
	umode_t mode = open_flags->mode; // Open mode
	const char * pathname = name->name;
	if (unlikely(pathname == NULL)) {
		pr_err("Path is NULL\n");
		return 0;
	}
	char * abs_path = kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
	if(IS_ERR(abs_path)) return 0;
	// check if the path belongs to a list to avoid excessive logs

	int err_abs = get_abs_path(pathname, abs_path);
	if(!is_valid_path(pathname)) {
		return 0;
	} else {
		INFO("absolute path is %s", abs_path);
		if(strcmp(abs_path, "") == 0) {
			pr_err("Unable to resolve the path, %d\n", err_abs);
			return 0;
		}
	}
	int check2 = strcmp(name->name, abs_path) == 0;
	for (int i = 0; i < 5; i++) {
		int check1 = strcmp(test_paths[i], name->name) == 0;
		if (check1) {
			pr_info("Path %s is in the test paths\n", name->name);

			INFO("File %s is being opened with flags %d and mode %d\n", name->name, flags, mode);
			// find used flags
			if(flags & O_CREAT) {
				pr_info("File %s is being created\n", name->name);
			}
			if(flags & O_WRONLY) {
				pr_info("File %s is being opened for writing\n", name->name);
			}
			if(flags & O_RDWR) {
				pr_info("File %s is being opened for reading and writing\n", name->name);
			}
			if(flags & O_TRUNC) {
				pr_info("File %s is being truncated\n", name->name);
			}
			if(flags & O_APPEND) {
				pr_info("File %s is being opened for appending\n", name->name);
			}
			if(flags & O_EXCL) {
				pr_info("File %s is being opened exclusively\n", name->name);
			}
			if(flags & O_NONBLOCK) {
				pr_info("File %s is being opened in non-blocking mode\n", name->name);
			}
			if(flags & O_SYNC) {
				pr_info("File %s is being opened in synchronous mode\n", name->name);
			}
			if(flags & O_DIRECT) {
				pr_info("File %s is being opened in direct mode\n", name->name);
			}
			if(flags & O_NOATIME) {
				pr_info("File %s is being opened with no access time\n", name->name);
			}
			if(flags & O_NOCTTY) {
				pr_info("File %s is being opened with no controlling terminal\n", name->name);
			}
			if(flags & O_PATH) {
				pr_info("File %s is being opened as a path\n", name->name);
			}
			if(flags & O_TMPFILE) {
				pr_info("File %s is being opened as a temporary file\n", name->name);
			}
			if(flags & O_CLOEXEC) {
				pr_info("File %s is being opened with close-on-exec flag\n", name->name);
			}
			if(flags & O_DIRECTORY) {
				pr_info("File %s is being opened as a directory\n", name->name);
			}
			if(flags & O_NOFOLLOW) {
				pr_info("File %s is being opened with no follow flag\n", name->name);
			}
			if(flags & O_LARGEFILE) {
				pr_info("File %s is being opened as a large file\n", name->name);
			}

		}

	}
	return 0;
}

// Kprobe definition
static struct kprobe kp = {
	.symbol_name = "do_filp_open", // Name of the function to probe
	.pre_handler = pre_do_filp_open, // Attach our pre-handler
};



static int test_path(const char *path) {
	if (unlikely(path == NULL)) {
		pr_err("Path is NULL\n");
		return -EINVAL;
	}
	if (unlikely(!is_valid_path(path))) {
		pr_err("Path is not valid\n");
		return -EINVAL;
	}
	return 0;
}



// Module initialization
static int __init kprobe_init(void)
{
	int ret;

	ret = register_kprobe(&kp); // Register the kprobe
	if (ret < 0) {
		printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
		return ret;
	}

	// test absolute path
	//pr_info("Testing absolute path resolving\n");
	//char *abs_path = kzalloc(PATH_MAX, GFP_KERNEL);
	//if (unlikely(abs_path == NULL)) {
	//	pr_err("Unable to allocate memory for the absolute path\n");
	//	return -ENOMEM;
	//}
	//char *parent_path = kzalloc(PATH_MAX, GFP_KERNEL);
	//if (unlikely(parent_path == NULL)) {
	//	pr_err("Unable to allocate memory for the absolute path\n");
	//	return -ENOMEM;
	//}
	//char *test_paths[5] = {
	//	reg_internal_file, internal_dir,
	//	reg_external_file, external_dir,
	//	re_external_dir_file
	//};
//
	//for (int i = 0; i < 5; i++) {
	//	int ret = get_abs_path(test_paths[i], abs_path);
	//	int parent_ret = get_dir_path(abs_path, parent_path);
	//	if (ret) {
	//		pr_err("Unable to resolve the path %s\n", test_paths[i]);
	//	} else {
	//		pr_info("Resolved path for %s is %s\n", test_paths[i], abs_path);
	//	}
	//	if (parent_ret) {
	//		pr_err("Unable to resolve the parent path %s\n", test_paths[i]);
	//	} else {
	//		pr_info("Resolved parent path for %s is %s\n", test_paths[i], parent_path);
	//	}
	//}
	//kfree(abs_path);
	//kfree(parent_path);
	printk(KERN_INFO "Kprobe registered for do_filp_open\n");

	return 0;
}

// Module exit
static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp); // Unregister the kprobe
	printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kprobe to detect open-on-write and creation operations with parent directory protection");
