# Status
The reference monitor can be in ONE among 4 status, implemented as an enum.
- OFF: ops disabled
- ON: ops enabled
- REC_ON: reconfigurable, ops enabled
- REC_OFF: reconfigurable, ops disabled

> Probably an implementation could provide only ON and OFF states and a reconfigurable bit. The REC_ON and REC_OFF states could be implemented as a combination of the other.

> ON and OFF aren't reconfigurable states, REC_ON and REC_OFF are. So the default state should be REC_OFF. Then the reference monitor can be turned on or off, and reconfigured.
> Feasible state transitions are:
> - REC_OFF <-> REC_ON
> - REC_ON -> ON, OFF
> - REC_OFF -> ON, OFF


# Configuration
The reference monitor can be reconfigured by adding or removing paths to be protected.
- REC_ON: paths can be added/removed
- REC_OFF: paths cannot be added/removed -> probably should be default state

If a path belongs to the set of protected paths, it cannot be opened in write mode, regardless of the user-id.
- This means that any attempt to write-open the path needs to return an error.

Changing the state of the reference monitor requires the thread to have effective-user-id set to root and a reference-monitor specific password.
- The password is given to the module when it is inserted into the kernel (possibly as a mandatory module parameter). 
- Then it's stored in encrypted form at the reference monitor level for performing the required checks (like).

## Reconfigure Operations
Possible steps for reconfiguration:
1. Checks if the reference monitor is in REC_ON/OFF state. If not, returns an error.
2. Checks if the thread has effective-user-id set to root. If not, asks for password. 
    - If password is *correct*, sets effective-user-id to root.
    - If password is *incorrect*, returns an error.
3. (Assuming root) Adds or removes paths to be protected. -> RCU_linked-list to keep paths? Maybe kSet?

> VFS or custom API for adding/removing paths?

# Reference Monitor
The reference monitor is a kernel module that hooks into the VFS layer to monitor file operations.
- It maintains a list of paths that are protected.
- It intercepts file operations and checks if the path is in the list of protected paths.
- If the path is in the list, it checks if the operation is allowed.
- If the operation is not allowed, it returns an error.

## Hooks
The reference monitor hooks into the VFS layer to monitor file operations.
- The hooks are implemented as function pointers in the reference monitor module.
- The hooks are registered with the VFS layer during module initialization.
- The hooks are unregistered during module cleanup.

The reference monitor hooks into the following VFS operations:
- open
- read
- write
- close
- unlink
- mkdir
- rmdir
- rename

## Data Structures
The reference monitor maintains the following data structures:
- A list of protected paths
- A list of function pointers for the VFS hooks

The list of protected paths is implemented as a linked list.
- Each node in the linked list contains the path and the permissions for the path.
- The permissions are implemented as a bitmask.

The list of function pointers for the VFS hooks is implemented as an array of function pointers.
- The array is indexed by the VFS operation number.
- Each element in the array is a function pointer to the hook function for that VFS operation.

## Hook Functions
The hook functions for the VFS operations are implemented as separate functions in the reference monitor module.
- Each hook function checks if the path is in the list of protected paths.
- If the path is in the list, the hook function checks if the operation is allowed.
- If the operation is not allowed, the hook function returns an error.

The hook functions are registered with the VFS layer during module initialization.
- The hook functions are unregistered during module cleanup.

# Module Initialization
The reference monitor module is initialized by the kernel when it is inserted into the kernel.
- During initialization, the module registers the hook functions with the VFS layer.
- The module also allocates memory for the data structures used by the reference monitor.

The module initialization function is called when the module is inserted into the kernel.
- The module initialization function registers the hook functions with the VFS layer.
- The module initialization function allocates memory for the data structures used by the reference monitor.

# Module Cleanup
The reference monitor module is cleaned up by the kernel when it is removed from the kernel.
- During cleanup, the module unregisters the hook functions from the VFS layer.
- The module also frees the memory allocated for the data structures used by the reference monitor.

The module cleanup function is called when the module is removed from the kernel.
- The module cleanup function unregisters the hook functions from the VFS layer.

# Testing
The reference monitor module can be tested by writing test cases that exercise the various VFS operations.
- The test cases should include paths that are in the list of protected paths and paths that are not in the list.
- The test cases should include operations that are allowed and operations that are not allowed.

The test cases should be run on a system with the reference monitor module loaded.
- The test cases should verify that the reference monitor correctly allows or denies the operations based on the list of protected paths.

