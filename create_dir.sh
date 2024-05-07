#!/bin/bash

# Define the directory path
dir="/etc/scripts"

# Check if the directory exists
if [ -d "$dir" ]; then
    echo "Directory already exists: $dir"
else
    # Attempt to create the directory
    echo "Directory does not exist, creating: $dir"
    mkdir -p "$dir"
    # Check if the mkdir command was successful
    if [ $? -eq 0 ]; then
        echo "Directory created successfully: $dir"
    else
        echo "Failed to create directory: $dir"
        exit 1
    fi
fi

# If the directory exists or was created successfully, exit with code 0
exit 0
