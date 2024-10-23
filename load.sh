#!/bin/bash
make clean >> /dev/null
make all >> /dev/null
# load the modules
#echo "Hacking the syscall table to insert our system calls..."
cd scth || exit
# hack the syscall table
make load
cd ..
cd loggerfs || exit
make load
make app
make create-fs
make mount-fs
cd ..
#printf "Loading the kReMFiP module...\nEnter a password to use when reconfiguring the monitor.\n"
# read the password and pass it to the module
read -rp "Password: " -s password  && echo
#echo "Password accepted."
sudo insmod kremfip.ko module_pwd="$password" LOG_FILE="$(realpath loggerfs/mount/logfile)"
#if [ $? -ne 0 ]; then
 #   echo "Failed to load the kReMFiP module."
 #   exit 1
#fi

#echo "kReMFiP module loaded."
