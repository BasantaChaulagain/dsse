#!/bin/bash

# Help option
if [ "$1" == "-h" ]; then
    echo "Usage: ./forensics.sh <'bt' or 'ft'> <log_file_name> <'p' or 'f'> <pid or inode>"
    echo "Options:"
    echo "  bt           Use backward tracking (AUDIT_bt)"
    echo "  ft           Use forward tracking (AUDIT_ft)"
    echo "  log_file_name  The name of the log file (include .csv)"
    echo "  p            Investigate a process ID (PID)"
    echo "  f            Investigate a file by inode"
    echo "  pid or inode   Enter pid if p is chosen, inode if f is chosen"
    exit 0
fi

# Navigate to the client directory
cd ../client

# Initialize the command variable
cmd=""

# Check the first argument
if [ "$1" == "bt" ]; then
    cmd="./AUDIT_bt -t "
elif [ "$1" == "ft" ]; then
    cmd="./AUDIT_ft -t "
else
    echo "Invalid entry for first argument. Use 'bt' for backward tracking or 'ft' for forward tracking."
    exit 1
fi

# Set the log file path
log_file="sample_data/${2}_init_table.dat"
cmd+="$log_file"

# Check if the log file exists
if [ ! -f "$log_file" ]; then
    ./AUDIT_bt -i "sample_data/${2}" -p 1
fi

# Check the third argument
if [ "$3" == "p" ]; then
    cmd+=" -p "
elif [ "$3" == "f" ]; then
    cmd+=" -f "
else
    echo "Invalid entry for third argument. Use 'p' for process ID or 'f' for file inode."
    exit 1
fi

# Add the fourth argument (PID or inode) to the command
cmd+="$4"

# Execute the constructed command
echo "Executing: $cmd"
$cmd

if [ "$1" == "bt" ]; then
    mv AUDIT_bt.gv ../investigator
elif [ "$1" == "ft" ]; then
    mv AUDIT_ft.gv ../investigator
fi