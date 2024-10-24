#!/bin/bash
# compile the module
echo "Compiling the module..."
make clean >> /dev/null
make all >> /dev/null
# load the modules
echo "Hacking the syscall table to insert our system calls..."
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
echo "Loading the kReMFiP module..."
echo "Enter a password to use when reconfiguring the monitor: "
# read the password and pass it to the module
read -rp "Password: " -s password  && echo
echo "Password accepted."
sudo insmod kremfip.ko module_pwd="$password" LOG_FILE="$(realpath loggerfs/mount/logfile)"
echo "kReMFiP module loaded."
