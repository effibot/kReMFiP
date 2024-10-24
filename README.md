# The kReMFiP Project

> a Kernel-level Reference Monitor for File Protection

_For the requested project specs go to [project_specs.md](project_specs.md)._

This project is a kernel module that implements a reference monitor for file protection. The reference monitor is implemented as combination of data structures that keeps track of:
1. **its configuration**, that is, the list of paths that are _protected from write_ operations,
2. and the **current state** of the reference monitor.

When _write-on-open_ operations are attempted on a protected path, the reference monitor should return an error, independently of the user-id that attempts the open operation and logs are written to a file accordingly to the project specs.


# The Components of the Project

## 1. The Hash Table with RCU Linked Lists

The monitor uses a hash table to keep track of the protected paths. This table is implemented using the kernel's built-in RCU double-linked lists to perform fast and safe lookups and insertions when the kernel needs to check if a path is protected or add a new path to the list of protected paths.

The keys of the table are generated as the hash of the path string and the values are the path strings themselves. The hash function used is a kernel-side port of the MurmurHash3 algorithm. More infos and details can be found at [[1]](https://en.wikipedia.org/wiki/MurmurHash) or [[2]](https://github.com/aappleby/smhasher/tree/master).

## 2. The SCTH module - System Call Table Hacker
This module is responsible for the hacking of the system call table to add a new system call. The new system calls are used to change the state of the reference monitor and reconfigure it. 

The hacking mechanism uses linear addressing to scan the kernel memory and search for some specific patterns that are characteristic of the system call table. Once the table is found, the module expose the free slots in the table and the user can choose which slot to use for the new system call. The programmer can find the `sys_ni_syscall` free slots inside `/sys/module/scth/sysnis`. 

The module also provides mechanism to add and remove new system calls from the table or to restore it to its original state.
> When a new syscall is added, a new number is inserted inside `/sys/module/scth/hsysnis` and the user can use this number to call the new syscall.

## 3. The LoggerFS module - The Device Driver
LoggerFS is another kernel module that implements a simple filesystem that logs the file accesses performed on protected paths. The filesystem is implemented as a single append-only file.

The core implementation is based on the kernel module developed by [Prof. Francesco Quaglia](https://francescoquaglia.github.io/) and can be found at [[3]](https://github.com/FrancescoQuaglia/FrancescoQuaglia.github.io/blob/master/TEACHING/AOS/AA-2023-2024/SOFTWARE/VIRTUAL-FILE-SYSTEM.tar). The original module is called _SingleFile-FS_.

## 4. The Reference Monitor

### About Monitor's State 

The monitor can be in one of the following four states: **OFF, ON, REC_OFF, REC_ON**. In the _reconfigurable_ states, paths can be added or removed from the list of protected paths.

This implementation uses an enum to represent the states and perform the necessary checks on state validity and user permissions. In fact, before changing the state or reconfiguring the monitor, the user's effective user id is elevated to root and only if the elevated user is root the operation is allowed.
> To perform the privilege escalation, the module uses the `creds` functions and ask the user to insert the module's password.

### About Monitor's Configuration
The monitor needs a password to be reconfigured. The password is stored in the module's folder under `/sys` and is hashed using the SHA256 algorithm. The hash is used to check the password's validity by comparing a freshly hashed password with the stored hash. 

For, obvious security reasons, the password is neither stored in the kernel nor in the user space. The password is passed to the kernel using a module argument and requested to the user with the help of GNU's `getpass` command. Once the password is passed to the kernel, it's hashed and removed from the kernel's memory.

### About Monitor's Operations - Kernel Probes and Device Driver Logging

For monitor's operations we mean, besides the state and configuration changes, the operations that the monitor performs when a write-on-open operation is attempted on a protected path. The hooked functions are `open`, `mkdir`, `rmdir`, and `unlink`. 

When a write-on-open operation is attempted on a protected path, the monitor logs the following tuple of data (per line of the file):
- the process TGID
- the thread ID
- the user-id
- the effective user-id
- the program path-name that is currently attempting the open
- a cryptographic hash of the program file content

The computation of the cryptographic hash and the writing of the above tuple is carried in deferred work to reduce the overhead of the kprobe handlers. The deferred work is implemented using the kernel's workqueue mechanism.

> NOTE: To interrupt the syscalls from completing their work, the monitor uses the `do_sys_open`, `do_sys_mkdir`, `do_sys_rmdir`, and `do_sys_unlink` functions as hooks. When a write-on-open operation is attempted on a protected path the monitor does, in order, the following operations:
> 1. Retrieve the absolute path of the opened resource and it's parent directory.
> 2. Check if the path is protected. If not, jumpt to the exit point and let the syscall complete its work.
> 3. If the path is protected:
>    1. If `do_sys_open` is the hooked function, the flags are changed to `O_RDONLY`. 
>    2. If `do_sys_mkdir`, `do_sys_rmdir`, or `do_sys_unlink` are the hooked functions, the `RAX` register is set to `NULL`.
> 4. The deferred work is scheduled and the syscall is interrupted by sending a signal to the process.

> NOTE: using `NULL` to stop the syscall is a trick to avoid the syscall to complete its work. The syscall is interrupted and the process is signaled to stop its work. However, this seems to be a bad practice as seems to panic the kernel. More work is needed to understand why this happens.
 
## The User Space Commands
The project includes a set of user space commands that can be used to interact with the reference monitor. The commands are:
- `getstate`: to get the current state of the reference monitor.
- `setstate -s <state>`: to set the state of the reference monitor. This accepts the following arguments: `0 (OFF)`, `1 (ON)`, `2 (REC_OFF)`, `3 (REC_ON)`. The validity of the argument is checked both by the user space command and by the kernel module.
- `reconfigure -o <operation> -p <path>`: to reconfigure the reference monitor. This accepts the following arguments: `0 (PROTECT_PATH)`, `1 (UNPROTECT_PATH)`. The validity of the argument is checked both by the user space command and by the kernel module. The path is the path to be added or removed from the list of protected paths. There's no need to check for validity of the path as the module resolve the path to its absolute path before adding it to the list of protected paths. If this resolution fails, the operation is aborted.

# How to Build and Run the Project
To build the project you need to have the kernel headers installed on your system. The project was developed and tested on a `Ubuntu 18.04 LTS` with kernel version `5.4.0-150-generic`. To install the programs to build the project, run the following commands (`apt` is used just as an example, you can use any package manager you like):
```bash
sudo apt update && sudo apt install build-essential linux-headers-$(uname -r) git
```
Now, you can clone the project and build it:
```bash
git clone https://github.com/effibot/kReMFiP.git
cd kReMFiP
./load.sh
```

The `load.sh` script will build the project and load the modules. The modules are loaded in the following order:
1. `scth` - System Call Table Hacker
2. `loggerfs` - The Device Driver
3. `kremfip` - The Reference Monitor

> User-space CLI commands are available in the `user/CLI` folder and they are built togheter with the kernel modules.
> Loading the module, create and mount the `loggerfs` filesystem. This is a volatile filesystem and it's destroyed when the module is unloaded.

To unload the modules, run the following command:
```bash
./unload.sh
```

# Project Structure
The project code-base, is structured as follows:
```bash
. kReMFiP
├── scth # System Call Table Hacker
│   ├──  headers # headers for the scth module - exposed to the user space also
│   │   └── scth_lib.h 
│   ├── test # helper module to test the scth module
│   ├── src 
│   │   ├── include
│   │   │   ├── scth_lib.c # library functions to interact with the syscall table
│   │   │   └── scth.h # header file for the scth module
│   │   ├── utils # utility functions to interact with the kernel and x86 assembly i.e. for CR0 protection
│   │   │   ├── paging_navigator.c
│   │   │   ├── x86_utils.h
│   │   │   └── paging_navigator.h
│   │   └── scth_main.c # init and exit functions for the scth module
├── user
│   ├── CLI
│   │   ├── setstate.c # user space command to set the state of the reference monitor
│   │   ├── getstate.c # user space command to get the state of the reference monitor
│   │   └── reconfigure.c # user space command to reconfigure the reference monitor
├── src
│   ├── user # user-space header and functions to interact with the reference monitor
│   │   ├── kremfip_lib.c 
│   │   └── kremfip_lib.h
│   ├── include 
│   │   ├── syscalls.c # kernel-side core-implementation syscalls
│   │   ├── rm.c # core-implementation of reference monitor, including kprobes and deferred work handlers.
│   │   ├── constants.h # module's constants
│   │   ├── kremfip.h # module's header file
│   │   └── rm.h # reference monitor's header file
│   ├── utils
│   │   ├── pathmgm.c # utility functions to manage paths
│   │   ├── misc.c # misc utility functions such as password hashing and enums-to-strings conversions
│   │   ├── pathmgm.h # header file for path management functions
│   │   └── misc.h # header file for misc utility functions
│   ├── lib
│   │   ├── hash # hash functions implementations
│   │   │   ├── murmurhash3.c
│   │   │   └── murmurhash3.h
│   │   └── ht_dll_rcu # Hash Table with double linked list and RCU synchronization
│   │       ├── ht_dllist.c
│   │       └── ht_dllist.h
│   └── kremfip_main.c #! CORE IMPLEMENTATION OF THE kReMFiP MODULE, including syscalls macro definitions.
├── loggerfs # The Device Driver
│   ├── src # needed file-operations to implement the driver
│   │   ├── operations.c
│   │   ├── makelogfs.c
│   │   ├── loggerfs_main.c
│   │   ├── operations.h
│   │   └── loggerfs.h
├── load.sh # Loading script
└── unload.sh # Unloading script
```
