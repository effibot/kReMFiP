# Key-Points
The reference monitor is a data structure with:
- a state
- a configuration, that is, a *collection* of protected paths.
- a password, not stored directly in the module.
- A device driver to log the file accesses on protected paths.

To intercept write-on-open operations, the reference monitor needs to hook into the VFS layer through the following operations:
- open
- mkdir
- rmdir
- unlink

> The hooking is done by registering specific kprobes for each of the operations.

# State

The reference monitor can be in ONE among 4 state, implemented as an enum.

- OFF: ops disabled
- ON: ops enabled
- REC_ON: reconfigurable, ops enabled -> we select this as the default state
- REC_OFF: reconfigurable, ops disabled

> When the operations are enabled, the kprobes are registered in the system.

# Configuration

The configuration is implemented as an hash table with linked lists for collision resolution. If a path is in the hash table, then it is protected. A path can be added or removed from the hash table only if the monitor is in a reconfigurable state.

>If a path belongs to the set of protected paths, it cannot be opened in write mode, regardless of the user-id.

- This means that any attempt to write-open the path needs to return an error.

# Password Handling
The password is stored in the reference monitor in encrypted form, under the _sys_ filesystem. The check of the hash is done using the sysfs API itself. To avoid attacks to the hash digest, we don't implement a store operation.

Changing the state of the reference monitor requires the thread to have effective-user-id set to root and a
reference-monitor specific password.

> The password is given to the module when it is inserted into the kernel as a parameter.


# Log File
The log file is an append-only file that records the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted. The tuple is:
<ul>
	<li>the process TGID
	<li>the thread ID
	<li>the user-id
	<li>the effective user-id
	<li>the program path-name that is currently attempting the open
	<li> a cryptographic hash of the program file content
</ul>