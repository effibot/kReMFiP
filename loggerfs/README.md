# LOGGER File System
## Description
LOGGER is a simple file system that logs all the operations performed on the file protected by the reference monitor.

## Features
The structure is made of 
```
------------------------------------------------------------------
| Block 0    | Block 1      | Block 2    | Block ... | Block n   |
| Superblock | inode of the | File data  | File data | File data |
|            | File         |            |           |           |
------------------------------------------------------------------
```
- Superblock: Contains the metadata of the file system.
- Inode: Contains the metadata of the file.
- File data: Contains the data of the file.

## Operations
The operations implemented let the system to log the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:
- the process TGID 
- the thread ID 
- the user-id 
- the effective user-id 
- the program path-name that is currently attempting the open
a cryptographic hash of the program file content

## Installation
To install the file system, just execute the makefile in this folder or the one in the parent folder.
