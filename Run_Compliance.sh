#!/bin/bash

# Define the path to the compliance script and the log file
script_path="/etc/scripts/compliance.sh"
log_file="/etc/scripts/Run_Compliance.log"

# Function to append output to log file
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$log_file"
}

# Start logging to the file
log "Checking for the compliance script."

# Check if the compliance script exists
if [ -f "$script_path" ]; then
    log "Found the compliance script at $script_path"

    # Check if the script is executable, if not, make it executable
    if [ ! -x "$script_path" ]; then
        log "Script is not executable, changing permissions..."
        chmod +x "$script_path"
        
        # Check if chmod succeeded
        if [ $? -ne 0 ]; then
            log "Failed to change permissions of the script."
            exit 1
        else
            log "Permissions changed successfully."
        fi
    fi

    log "Executing the compliance script with --cfc option..."
    # Execute the script with the --cfc option
    "$script_path" --cfc

    # Check the exit status of the script
    if [ $? -eq 0 ]; then
        log "Script executed successfully."
    else
        log "Script execution failed with status $?."
        exit 1
    fi
else
    log "Error: Script not found at $script_path"
    exit 1
fi

# Successful exit
log "Operation completed successfully."
exit 0
