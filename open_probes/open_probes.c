
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>


// Declaration of the is_protected function (you'll need to implement it)
extern int is_protected(const char *path){
	if(strcmp(path,"/home/effi/file0.txt") == 0){
		pr_info("%s is protected", path);
        return 1;
    }
	if(strcmp(path,"/home/effi/file1.txt") == 0){
		pr_info("%s is protected", path);
        return 1;
    }
	if(strcmp(path,"/home/effi/Downloads") == 0){
		pr_info("%s is protected", path);
        return 1;
    }
	if(strcmp(path, "/home/effi/testdir") == 0){
		pr_info("%s is protected", path);
		return 1;
	}
	return 0;
}

// Struct representing flags passed to open syscall
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

#define INVALID_PATHS_NUM 24
static const char *invalid_paths[INVALID_PATHS_NUM] = {
	"/bin", "/boot", "/cdrom", "/dev", "/etc", "/lib", "/lib64", "/mnt", "/opt", "/proc",
	"/root", "/run", "/sbin", "/snap", "/srv", "/swapfile", "/sys", "/usr", "/var", "/tmp",
	"/home/effi/.cache","/home/effi/.java", "/home/effi/.Xauthority", ".git",

};

char *get_pwd(void){

	struct path abs_path;
	char *buf, *full_path;

	buf = kmalloc(1024,GFP_KERNEL);
	if(buf == NULL) return "";

	get_fs_pwd(current->fs, &abs_path);

	full_path = dentry_path_raw(abs_path.dentry, buf, PATH_MAX);
	kfree(buf);
	return full_path;

}
// Helper function to resolve the parent directory path
static char *resolve_parent_path(const char *file_path)
{
	int i= strlen(file_path)-1;
	char *new_string = kzalloc(strlen(file_path), GFP_KERNEL);
	if(new_string == NULL)  return "";

	while(i>=0){
		if(file_path[i] != '/'){
			new_string[i] = '\0';
		}
		else{
			new_string[i]='\0';
			i--;
			break;
		}
		i--;
	}

	while(i>=0){
		new_string[i] = file_path[i];
		i--;
	}
	if(new_string[strlen(new_string)] == '/')
		new_string[strlen(new_string)] = '\0';

	pr_info("found %s", new_string);
	if(new_string[0] != '/'){
		pr_info("found non absolute");
		struct path path_struct;
		char * pwd = get_pwd();
		char * pwd_to_path = kzalloc(PATH_MAX, GFP_KERNEL);
		strscpy(pwd_to_path, pwd, PATH_MAX);
		pwd_to_path[strlen(pwd_to_path)]='/';
		strcat(pwd_to_path, new_string);
		if(kern_path(pwd_to_path, LOOKUP_FOLLOW, &path_struct)){
				pr_warn("kern path fail");
				kfree(pwd_to_path);
				return new_string;
		}
		pr_info("%c",pwd_to_path[strlen(pwd_to_path)]);
		if(pwd_to_path[strlen(pwd_to_path)-1] == '/')
			pwd_to_path[strlen(pwd_to_path)-1] = '\0';

		path_put(&path_struct);
		return pwd_to_path;
	}
	return new_string;
}
// Check if path starts with an invalid path prefix
static bool is_invalid_path(const char *path) {
	for (int i = 0; i < INVALID_PATHS_NUM; i++) {
		if (str_has_prefix(path, invalid_paths[i])) {
			return true;
		}
	}
	return false;
}



// Pre-handler for the kprobe
static int pre_do_filp_open(struct kprobe *p, struct pt_regs *regs) {
	struct filename *pathname;
	int flags;
	char *resolved_path = NULL;
	char *tpath = NULL;
	int ret = 0;
	char *parent_path = NULL;

	// Extract arguments from the do_filp_open signature
	// `regs->di` contains the `dfd` (AT_FDCWD or directory fd)
	// `regs->si` contains the pointer to the `filename` structure
	// `regs->dx` contains the pointer to `open_flags`

//#if defined(CONFIG_X86_64)
	pathname = (struct filename *)regs->si; // Second argument (filename)
	flags = ((struct open_flags *)regs->dx)->open_flag; // Third argument (flags)
//#endif
	if (is_invalid_path(pathname->name)) {

		return 0;
	}

	// Check if the open flags include write access or creation
	if (!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL))) {
		// Allocate memory for the temporary path
		tpath = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tpath)
			return -ENOMEM;

		// Use the `name` member of `filename` structure to get the path string
		resolved_path = pathname->name;
		if (!resolved_path) {
			printk(KERN_ERR "Failed to retrieve filename path\n");
			ret = -EINVAL;
			goto out;
		}

		// Log the path for debugging
		printk(KERN_INFO "Opening path: %s with flags: %x\n", resolved_path, flags);

		// If O_CREAT is set, check the parent directory
		//if (flags & O_CREAT) {

//		// Check if the file itself is protected
//		if (is_protected(resolved_path)) {
//			printk(KERN_ALERT "Attempt to open a protected file: %s\n", resolved_path);
//
//			// If the file is protected, change the open flags to read-only (O_RDONLY)
//			flags &= ~(O_WRONLY | O_RDWR);
//			flags |= O_RDONLY;
//
//			// #if defined(CONFIG_X86_64)
//			((struct open_flags *)regs->dx)->open_flag = flags;
//			// #endif
//
//			printk(KERN_INFO "Downgrading open flags to read-only for protected file: %s\n",
//				   resolved_path);
//			goto out;
//		}
//
//		// Get the parent directory path
//
//		parent_path = resolve_parent_path(resolved_path);
//		int to_be_created = 0;
//		printk(KERN_INFO "Parent directory: %s\n", parent_path);
//		if (strcmp(parent_path, "") == 0) {
//			kfree(parent_path);
//			parent_path = get_pwd();
//		}
//		if (flags & O_CREAT) {
//			to_be_created = 1;
//		}
//		// Check if the parent directory is protected
//		if (to_be_created == 1) {
//			if (is_protected(parent_path)) {
//				printk(KERN_ALERT "Attempt to create a file in a protected directory: %s\n",
//					   parent_path);
//
//				// Change the flags to O_RDONLY, disallowing the creation
//				flags &= ~(O_WRONLY | O_RDWR | O_CREAT);
//				flags |= O_RDONLY;
//				//
//				//#if defined(CONFIG_X86_64)
//				((struct open_flags *)regs->dx)->open_flag = flags;
//				//#endif
//				//					regs->si = (unsigned long) NULL;
//				printk(KERN_INFO
//					   "Downgrading open flags to read-only for file in protected directory: %s\n",
//					   parent_path);
//			}
//		}

	}


out:
	if (tpath) {
		kfree(tpath);
	}

	//	if(parent_path){
	//		kfree(parent_path);
	//	}
	return ret;
}




// Kprobe definition
static struct kprobe kp = {
    .symbol_name = "do_filp_open",  // Name of the function to probe
    .pre_handler = pre_do_filp_open, // Attach our pre-handler
};

// Module initialization
static int __init kprobe_init(void)
{
    int ret;

    ret = register_kprobe(&kp); // Register the kprobe
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
        return ret;
    }

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
