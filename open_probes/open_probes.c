#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/fcntl.h>

#define INVALID_PATHS_NUM 20
static const char *invalid_paths[INVALID_PATHS_NUM] = {
    "/bin", "/boot", "/cdrom", "/dev", "/etc", "/lib", "/lib64", "/mnt", "/opt", "/proc",
    "/root", "/run", "/sbin", "/snap", "/srv", "/swapfile", "/sys", "/usr", "/var", "/tmp"
};

// Struct representing flags passed to open syscall
struct open_flags {
    int open_flag;
    umode_t mode;
    int acc_mode;
    int intent;
    int lookup_flags;
};

// Check if path starts with an invalid path prefix
static bool is_invalid_path(const char *path) {
    for (int i = 0; i < INVALID_PATHS_NUM; i++) {
        if (str_has_prefix(path, invalid_paths[i])) {
            return true;
        }
    }
    return false;
}

// Check if open flags are write-related
static bool is_write_operation(int flags) {
    // Check if the file is being opened with write permissions or for creation
    if ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_TMPFILE)) != 0) {
        return true;
    }
    return false;
}

// Function to resolve the absolute path
static int resolve_abs_path(int dfd, const __user char *user_path, char* store_buffer) {
    struct path path;
    unsigned int lookup_flags = LOOKUP_FOLLOW;
    int error;

    char tpath[PATH_MAX];  // Stack allocation for better performance
    error = user_path_at(dfd, user_path, lookup_flags, &path);
    if (error){
        return error;
    }
    char *ret_ptr = d_path(&path, tpath, sizeof(tpath));
    if (IS_ERR(ret_ptr))
        return PTR_ERR(ret_ptr);

    strscpy(store_buffer, ret_ptr, PATH_MAX);  // Copy resolved path to buffer
    return 0;
}

// Pre-handler for the kprobe
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    const int dfd = regs->di;
    const struct filename *fname = (const struct filename *)regs->si;
    const struct open_flags *op = (const struct open_flags *)regs->dx;
    char abs_path[PATH_MAX];  // Stack buffer

    // Check if the open syscall is for writing or creating a file
    if (!is_write_operation(op->open_flag)) {
        return 0;  // Skip probing if it's not a write-related operation
    }

    if (fname->uptr && access_ok(fname->uptr, PATH_MAX)) {
        if (resolve_abs_path(dfd, fname->uptr, abs_path) == 0) {
            if (!is_invalid_path(abs_path)) {
                printk(KERN_INFO "Opening file: %s with flags: %u\n", abs_path, op->open_flag);
            } else {
                return 0;  // Skip probing for system folders
            }
        }
    } else {
        printk(KERN_ERR "Invalid or inaccessible user path pointer\n");
    }

    return 0;  // Allow the open call to proceed
}

static struct kprobe kp = {
    .symbol_name = "do_filp_open",
    .pre_handler = handler_pre,
};

// Module initialization
static int __init kprobe_init(void) {
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "Kprobe registered\n");
    return 0;
}

// Module cleanup
static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    const __user char *user_path = "/home/effi/Desktop/open_probes/open_probes.c";
    char abs_path[PATH_MAX];  // Stack buffer
    int ret = resolve_abs_path(AT_FDCWD, user_path, abs_path);
    printk(KERN_INFO "Resolved path: %s\n", abs_path);
    printk(KERN_INFO "err: %d\n", ret);
    printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
