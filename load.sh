#!/bin/bash
make all >> /dev/null
printf "Loading the kReMFiP module...\nEnter a password to use when reconfiguring the monitor.\n"
# read the password and pass it to the module
read -rp "Password: " -s password  && echo
echo "Password accepted."
sudo insmod kremfip.ko module_pwd="$password"
echo "kReMFiP module loaded."