#!/bin/bash
# unload the modules
# first we need to unload the monitor
#echo "Removing the Reference Monitor..."
sudo rmmod kremfip
#echo "Done. Restoring the Syscall Table..."
sudo rmmod scth
#echo "Done. All Clear."
