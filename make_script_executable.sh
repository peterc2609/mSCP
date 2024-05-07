#!/bin/bash

# Set the full path to the file
file="/etc/scripts/compliance.sh"

# Check if the file exists
if [ -f "$file" ]; then
    echo "File found: $file"
    # Change the file's permissions to make it executable
    chmod +x "$file"
    # Check if chmod was successful
    if [ $? -eq 0 ]; then
        echo "File is now executable: $file"
    else
        echo "Failed to change permissions of the file: $file"
        exit 1
    fi
else
    echo "File does not exist: $file"
    # Optionally, you can create the file or exit with an error
    # Uncomment the following lines to create the file and make it executable if it does not exist
    # touch "$file"
    # chmod +x "$file"
    # echo "File created and made executable: $file"
fi

# If everything executed successfully, exit with code 0
exit 0
