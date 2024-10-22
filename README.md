# kReMFiP

a Kernel-level Reference Monitor for File Protection

### Checklist

- [x] Implemented a kernel module that hacks the system call table to add a new system call.
- [x] Implemented a hash table, using the kernel'd built-in RCU linked lists.
- [x] Implemented a data structure for the reference monitor
- [x] Implemented the password management, asking for the password as a module parameter and then removing it from the
  kernel memory.
- [x] The password's hash is stored insyde the relative module's folder under /sys. Only show operation is implemented
  to avoid security issues.
- [ ] Kprobes to hook open, mkdir, rmdir, unlink system calls.
- [x] Asks for the password when the set_state syscall is invoked.
- [x] Be sure to check for monitor state before invoking the reconfigure syscall.
- [ ] Implement the device driver to logs the file accesses performed on protected paths.
- [ ] implement the deferred work to compute the hash and write the log file.
- [x] add permission changing when reconfiguring the reference monitor
- [x] Checks user's effective user id when reconfiguring the reference monitor.
- [x] Add spinlocks to protect multiple reconfigure calls or set_state calls.

