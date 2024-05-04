#!/bin/zsh --no-rcs

##  This script will attempt to audit all of the settings based on the installed profile.

##  This script is provided as-is and should be fully tested on a system that is not in a production environment.

###################  Variables  ###################

pwpolicy_file=""

###################  DEBUG MODE - hold shift when running the script  ###################

shiftKeyDown=$(osascript -l JavaScript -e "ObjC.import('Cocoa'); ($.NSEvent.modifierFlags & $.NSEventModifierFlagShift) > 1")

if [[ $shiftKeyDown == "true" ]]; then
    echo "-----DEBUG-----"
    set -o xtrace -o verbose
fi

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

ssh_key_check=0
if /usr/sbin/sshd -T &> /dev/null || /usr/sbin/sshd -G &>/dev/null; then
    ssh_key_check=0
else
    /usr/bin/ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
    ssh_key_check=1
fi

# path to PlistBuddy
plb="/usr/libexec/PlistBuddy"

# get the currently logged in user
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }')
CURR_USER_UID=$(/usr/bin/id -u $CURRENT_USER)

# get system architecture
arch=$(/usr/bin/arch)

# configure colors for text
RED='\e[31m'
STD='\e[39m'
GREEN='\e[32m'
YELLOW='\e[33m'

audit_plist="/Library/Preferences/org.auditrules.audit.plist"
audit_log="/Library/Logs/auditrules_baseline.log"

# pause function
#pause(){
#vared -p "Press [Enter] key to continue..." -c fackEnterKey
#}

# Modify the pause function to skip pausing.
pause(){
    return 0
}

# logging function
logmessage(){
    if [[ ! $quiet ]];then
        echo "$(date -u) $1" | /usr/bin/tee -a "$audit_log"
    elif [[ ${quiet[2][2]} == 1 ]];then
        if [[ $1 == *" failed"* ]] || [[ $1 == *"exemption"* ]] ;then
            echo "$(date -u) $1" | /usr/bin/tee -a "$audit_log"
        else
            echo "$(date -u) $1" | /usr/bin/tee -a "$audit_log" > /dev/null
        fi
    else
        echo "$(date -u) $1" | /usr/bin/tee -a "$audit_log" > /dev/null
    fi
}

#ask() {
#    # if fix flag is passed, assume YES for everything
#    if [[ $fix ]] || [[ $cfc ]]; then
#        return 0
#    fi
#
#    while true; do
#
#        if [ "${2:-}" = "Y" ]; then
#            prompt="Y/n"
#            default=Y
#        elif [ "${2:-}" = "N" ]; then
#            prompt="y/N"
#            default=N
#        else
#            prompt="y/n"
#            default=
#       fi

# Modify the ask function to always return true (yes).
ask() {
    return 0
}

#        # Ask the question - use /dev/tty in case stdin is redirected from somewhere else
#        printf "${YELLOW} $1 [$prompt] ${STD}"
#        read REPLY#
#
#        # Default?
#        if [ -z "$REPLY" ]; then
#            REPLY=$default
#        fi
#
#        # Check if the reply is valid
#        case "$REPLY" in
#            Y*|y*) return 0 ;;
#            N*|n*) return 1 ;;
#        esac
#   done
#}

# function to display menus
#show_menus() {
#    lastComplianceScan=$(defaults read /Library/Preferences/org.auditrules.audit.plist lastComplianceCheck)
#
#    if [[ $lastComplianceScan == "" ]];then
#        lastComplianceScan="No scans have been run"
#    fi
#
#    /usr/bin/clear
#    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#    echo "        M A I N - M E N U"
#    echo "  macOS Security Compliance Tool"
#    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#    echo "Last compliance scan: $lastComplianceScan
#"
 #   echo "1. View Last Compliance Report"
 #   echo "2. Run New Compliance Scan"
 #   echo "3. Run Commands to remediate non-compliant settings"
 #   echo "4. Exit"
#}

# If using menus, bypass or set default actions directly
show_menus() {
    run_scan  # Directly run the scan without menu interaction
}

# function to read options
#read_options(){
#    local choice
#    vared -p "Enter choice [ 1 - 4 ] " -c choice
#    case $choice in
#        1) view_report ;;
#        2) run_scan ;;
#        3) run_fix ;;
#        4) exit 0;;
#        *) echo -e "${RED}Error: please choose an option 1-4...${STD}" && sleep 1
#    esac
#}

read_options(){
    run_scan  # Directly run the scan without menu interaction
}

# function to reset and remove plist file.  Used to clear out any previous findings
reset_plist(){
    if [[ $reset_all ]];then
        echo "Clearing results from all MSCP baselines"
        find /Library/Preferences -name "org.*.audit.plist" -exec rm -f '{}' \;
        find /Library/Logs -name "*_baseline.log" -exec rm -f '{}' \;
    else
        echo "Clearing results from /Library/Preferences/org.auditrules.audit.plist"
        rm -f /Library/Preferences/org.auditrules.audit.plist
        rm -f /Library/Logs/auditrules_baseline.log
    fi
}

# Generate the Compliant and Non-Compliant counts. Returns: Array (Compliant, Non-Compliant)
compliance_count(){
    compliant=0
    non_compliant=0
    exempt_count=0
    
    rule_names=($(/usr/libexec/PlistBuddy -c "Print" $audit_plist | awk '/= Dict/ {print $1}'))
    
    for rule in ${rule_names[@]}; do
        finding=$(/usr/libexec/PlistBuddy -c "Print $rule:finding" $audit_plist)
        if [[ $finding == "false" ]];then
            compliant=$((compliant+1))
        elif [[ $finding == "true" ]];then
            is_exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey("$rule"))["exempt"]
EOS
)
            if [[ $is_exempt == "1" ]]; then
                exempt_count=$((exempt_count+1))
                non_compliant=$((non_compliant+1))
            else    
                non_compliant=$((non_compliant+1))
            fi
        fi
    done

    # Enable output of just the compliant or non-compliant numbers.
    if [[ $1 = "compliant" ]]
    then
        echo $compliant
    elif [[ $1 = "non-compliant" ]]
    then
        echo $non_compliant
    else # no matching args output the array
        array=($compliant $non_compliant $exempt_count)
        echo ${array[@]}
    fi
}

generate_report(){
    count=($(compliance_count))
    compliant=${count[1]}
    non_compliant=${count[2]}
    exempt_rules=${count[3]}

    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( (compliant + exempt_rules) * 100. / total )) )
    echo
    echo "Number of tests passed: ${GREEN}$compliant${STD}"
    echo "Number of test FAILED: ${RED}$non_compliant${STD}"
    echo "Number of exempt rules: ${YELLOW}$exempt_rules${STD}"
    echo "You are ${YELLOW}$percentage%${STD} percent compliant!"
    pause
}

view_report(){

    if [[ $lastComplianceScan == "No scans have been run" ]];then
        echo "no report to run, please run new scan"
        pause
    else
        generate_report
    fi
}

# Designed for use with MDM - single unformatted output of the Compliance Report
generate_stats(){
    count=($(compliance_count))
    compliant=${count[1]}
    non_compliant=${count[2]}

    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    echo "PASSED: $compliant FAILED: $non_compliant, $percentage percent compliant!"
}

run_scan(){
# append to existing logfile
if [[ $(/usr/bin/tail -n 1 "$audit_log" 2>/dev/null) = *"Remediation complete" ]]; then
 	echo "$(date -u) Beginning auditrules baseline scan" >> "$audit_log"
else
 	echo "$(date -u) Beginning auditrules baseline scan" > "$audit_log"
fi

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
/usr/bin/defaults write "$audit_plist" lastComplianceCheck "$(date)"
    
#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_files_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_files_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_acls_files_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_acls_files_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_acls_files_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_acls_files_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_acls_files_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_acls_files_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_acls_files_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_acls_files_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_acls_files_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_acls_files_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_acls_files_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -lde /var/audit | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_folders_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_folders_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_acls_folders_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_acls_folders_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_acls_folders_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_acls_folders_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_acls_folders_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_acls_folders_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_acls_folders_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_acls_folders_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_acls_folders_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_acls_folders_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_acls_folders_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)
AUDITD_RUNNING=$(/usr/sbin/audit -c | /usr/bin/grep -c "AUC_AUDITING")
if [[ $LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]] && [[ $AUDITD_RUNNING == 1 ]]; then
  echo "pass"
else
  echo "fail"
fi
)
    # expected result {'string': 'pass'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_auditd_enabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_auditd_enabled'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_auditd_enabled" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "pass" ]]; then
        logmessage "audit_auditd_enabled passed (Result: $result_value, Expected: \"{'string': 'pass'}\")"
        /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_auditd_enabled" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_auditd_enabled passed (Result: $result_value, Expected: "{'string': 'pass'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_auditd_enabled failed (Result: $result_value, Expected: \"{'string': 'pass'}\")"
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_auditd_enabled" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_auditd_enabled failed (Result: $result_value, Expected: "{'string': 'pass'}")"
        else
            logmessage "audit_auditd_enabled failed (Result: $result_value, Expected: \"{'string': 'pass'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_auditd_enabled" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_auditd_enabled failed (Result: $result_value, Expected: "{'string': 'pass'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_auditd_enabled does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: audit_control_acls_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -le /etc/security/audit_control | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_acls_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_acls_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_control_acls_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_control_acls_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_control_acls_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_control_acls_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_control_acls_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_acls_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_acls_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_control_acls_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_acls_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_acls_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_control_acls_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_control_acls_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_control_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $4}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_group_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_control_group_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_control_group_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_control_group_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_control_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_control_group_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_group_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_control_group_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_group_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_control_group_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_control_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_control_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -l /etc/security/audit_control | /usr/bin/awk '!/-r--[r-]-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/xargs
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_mode_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_mode_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_control_mode_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_control_mode_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_control_mode_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_control_mode_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_control_mode_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_mode_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_control_mode_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_mode_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_control_mode_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_control_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_control_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $3}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_owner_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_owner_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_control_owner_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_control_owner_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_control_owner_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_control_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_control_owner_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_owner_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_control_owner_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_control_owner_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_control_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_control_owner_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_control_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_group_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_files_group_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_files_group_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_files_group_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_files_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_files_group_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_files_group_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_files_group_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_files_group_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_files_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_files_group_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_files_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_mode_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_mode_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_files_mode_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_files_mode_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_files_mode_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_files_mode_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_files_mode_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_files_mode_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_files_mode_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_files_mode_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_files_mode_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_files_mode_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_files_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_owner_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_owner_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_files_owner_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_files_owner_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_files_owner_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_files_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_files_owner_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_files_owner_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_files_owner_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_files_owner_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_files_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_files_owner_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_files_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_group_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_group_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_folder_group_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_folder_group_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_folder_group_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_folder_group_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_folder_group_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_folder_group_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_folder_group_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_folder_group_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_folder_group_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_folder_group_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_folder_group_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_owner_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_owner_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_folder_owner_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "audit_folder_owner_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_folder_owner_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_folder_owner_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_folder_owner_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_folder_owner_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "audit_folder_owner_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_folder_owner_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_folder_owner_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_folder_owner_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_folder_owner_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
)
    # expected result {'integer': 700}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folders_mode_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folders_mode_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_folders_mode_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "700" ]]; then
        logmessage "audit_folders_mode_configure passed (Result: $result_value, Expected: \"{'integer': 700}\")"
        /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_folders_mode_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_folders_mode_configure passed (Result: $result_value, Expected: "{'integer': 700}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_folders_mode_configure failed (Result: $result_value, Expected: \"{'integer': 700}\")"
            /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_folders_mode_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}")"
        else
            logmessage "audit_folders_mode_configure failed (Result: $result_value, Expected: \"{'integer': 700}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_folders_mode_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_folders_mode_configure failed (Result: $result_value, Expected: "{'integer': 700}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_folders_mode_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_folders_mode_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control
)
    # expected result {'string': '60d or 5g'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_retention_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_retention_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "audit_retention_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "60d OR 5G" ]]; then
        logmessage "audit_retention_configure passed (Result: $result_value, Expected: \"{'string': '60d or 5g'}\")"
        /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "audit_retention_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: auditrules - audit_retention_configure passed (Result: $result_value, Expected: "{'string': '60d or 5g'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "audit_retention_configure failed (Result: $result_value, Expected: \"{'string': '60d or 5g'}\")"
            /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_retention_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_retention_configure failed (Result: $result_value, Expected: "{'string': '60d or 5g'}")"
        else
            logmessage "audit_retention_configure failed (Result: $result_value, Expected: \"{'string': '60d or 5g'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "audit_retention_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: auditrules - audit_retention_configure failed (Result: $result_value, Expected: "{'string': '60d or 5g'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "audit_retention_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
fi
    
lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)
echo "Results written to $audit_plist"

if [[ ! $check ]] && [[ ! $cfc ]];then
    pause
fi

} 2>/dev/null

run_fix(){

if [[ ! -e "$audit_plist" ]]; then
    echo "Audit plist doesn't exist, please run Audit Check First" | tee -a "$audit_log"

    if [[ ! $fix ]]; then
        pause
        show_menus
        read_options
    else
        exit 1
    fi
fi

if [[ ! $fix ]] && [[ ! $cfc ]]; then
    ask 'THE SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER. WOULD YOU LIKE TO CONTINUE? ' N

    if [[ $? != 0 ]]; then
        show_menus
        read_options
    fi
fi

# append to existing logfile
echo "$(date -u) Beginning remediation of non-compliant settings" >> "$audit_log"

# remove uchg on audit_control
/usr/bin/chflags nouchg /etc/security/audit_control

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID


    
#####----- Rule: audit_acls_files_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_files_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_files_configure'))["exempt_reason"]
EOS
)

audit_acls_files_configure_audit_score=$($plb -c "print audit_acls_files_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_acls_files_configure_audit_score == "true" ]]; then
        ask 'audit_acls_files_configure - Run the command(s)-> /bin/chmod -RN /var/audit ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_acls_files_configure ..."
            /bin/chmod -RN /var/audit
        fi
    else
        logmessage "Settings for: audit_acls_files_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_acls_files_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_acls_folders_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_folders_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_acls_folders_configure'))["exempt_reason"]
EOS
)

audit_acls_folders_configure_audit_score=$($plb -c "print audit_acls_folders_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_acls_folders_configure_audit_score == "true" ]]; then
        ask 'audit_acls_folders_configure - Run the command(s)-> /bin/chmod -N /var/audit ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_acls_folders_configure ..."
            /bin/chmod -N /var/audit
        fi
    else
        logmessage "Settings for: audit_acls_folders_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_acls_folders_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_auditd_enabled'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_auditd_enabled'))["exempt_reason"]
EOS
)

audit_auditd_enabled_audit_score=$($plb -c "print audit_auditd_enabled:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_auditd_enabled_audit_score == "true" ]]; then
        ask 'audit_auditd_enabled - Run the command(s)-> if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
fi

/bin/launchctl enable system/com.apple.auditd
/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist
/usr/sbin/audit -i ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_auditd_enabled ..."
            if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
fi

/bin/launchctl enable system/com.apple.auditd
/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist
/usr/sbin/audit -i
        fi
    else
        logmessage "Settings for: audit_auditd_enabled already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_auditd_enabled has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_control_acls_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_acls_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_acls_configure'))["exempt_reason"]
EOS
)

audit_control_acls_configure_audit_score=$($plb -c "print audit_control_acls_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_control_acls_configure_audit_score == "true" ]]; then
        ask 'audit_control_acls_configure - Run the command(s)-> /bin/chmod -N /etc/security/audit_control ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_control_acls_configure ..."
            /bin/chmod -N /etc/security/audit_control
        fi
    else
        logmessage "Settings for: audit_control_acls_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_control_acls_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_control_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_group_configure'))["exempt_reason"]
EOS
)

audit_control_group_configure_audit_score=$($plb -c "print audit_control_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_control_group_configure_audit_score == "true" ]]; then
        ask 'audit_control_group_configure - Run the command(s)-> /usr/bin/chgrp wheel /etc/security/audit_control ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_control_group_configure ..."
            /usr/bin/chgrp wheel /etc/security/audit_control
        fi
    else
        logmessage "Settings for: audit_control_group_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_control_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_control_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_mode_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_mode_configure'))["exempt_reason"]
EOS
)

audit_control_mode_configure_audit_score=$($plb -c "print audit_control_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_control_mode_configure_audit_score == "true" ]]; then
        ask 'audit_control_mode_configure - Run the command(s)-> /bin/chmod 440 /etc/security/audit_control ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_control_mode_configure ..."
            /bin/chmod 440 /etc/security/audit_control
        fi
    else
        logmessage "Settings for: audit_control_mode_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_control_mode_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_control_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_owner_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_control_owner_configure'))["exempt_reason"]
EOS
)

audit_control_owner_configure_audit_score=$($plb -c "print audit_control_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_control_owner_configure_audit_score == "true" ]]; then
        ask 'audit_control_owner_configure - Run the command(s)-> /usr/sbin/chown root /etc/security/audit_control ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_control_owner_configure ..."
            /usr/sbin/chown root /etc/security/audit_control
        fi
    else
        logmessage "Settings for: audit_control_owner_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_control_owner_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_files_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_group_configure'))["exempt_reason"]
EOS
)

audit_files_group_configure_audit_score=$($plb -c "print audit_files_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_group_configure_audit_score == "true" ]]; then
        ask 'audit_files_group_configure - Run the command(s)-> /usr/bin/chgrp -R wheel /var/audit/* ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_files_group_configure ..."
            /usr/bin/chgrp -R wheel /var/audit/*
        fi
    else
        logmessage "Settings for: audit_files_group_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_files_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_files_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_mode_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_mode_configure'))["exempt_reason"]
EOS
)

audit_files_mode_configure_audit_score=$($plb -c "print audit_files_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_mode_configure_audit_score == "true" ]]; then
        ask 'audit_files_mode_configure - Run the command(s)-> /bin/chmod 440 /var/audit/* ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_files_mode_configure ..."
            /bin/chmod 440 /var/audit/*
        fi
    else
        logmessage "Settings for: audit_files_mode_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_files_mode_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_files_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_owner_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_files_owner_configure'))["exempt_reason"]
EOS
)

audit_files_owner_configure_audit_score=$($plb -c "print audit_files_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_files_owner_configure_audit_score == "true" ]]; then
        ask 'audit_files_owner_configure - Run the command(s)-> /usr/sbin/chown -R root /var/audit/* ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_files_owner_configure ..."
            /usr/sbin/chown -R root /var/audit/*
        fi
    else
        logmessage "Settings for: audit_files_owner_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_files_owner_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_folder_group_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_group_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_group_configure'))["exempt_reason"]
EOS
)

audit_folder_group_configure_audit_score=$($plb -c "print audit_folder_group_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_folder_group_configure_audit_score == "true" ]]; then
        ask 'audit_folder_group_configure - Run the command(s)-> /usr/bin/chgrp wheel /var/audit ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_folder_group_configure ..."
            /usr/bin/chgrp wheel /var/audit
        fi
    else
        logmessage "Settings for: audit_folder_group_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_folder_group_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_folder_owner_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_owner_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folder_owner_configure'))["exempt_reason"]
EOS
)

audit_folder_owner_configure_audit_score=$($plb -c "print audit_folder_owner_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_folder_owner_configure_audit_score == "true" ]]; then
        ask 'audit_folder_owner_configure - Run the command(s)-> /usr/sbin/chown root /var/audit ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_folder_owner_configure ..."
            /usr/sbin/chown root /var/audit
        fi
    else
        logmessage "Settings for: audit_folder_owner_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_folder_owner_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_folders_mode_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-9

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folders_mode_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_folders_mode_configure'))["exempt_reason"]
EOS
)

audit_folders_mode_configure_audit_score=$($plb -c "print audit_folders_mode_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_folders_mode_configure_audit_score == "true" ]]; then
        ask 'audit_folders_mode_configure - Run the command(s)-> /bin/chmod 700 /var/audit ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_folders_mode_configure ..."
            /bin/chmod 700 /var/audit
        fi
    else
        logmessage "Settings for: audit_folders_mode_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_folders_mode_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: audit_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_retention_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.auditrules.audit').objectForKey('audit_retention_configure'))["exempt_reason"]
EOS
)

audit_retention_configure_audit_score=$($plb -c "print audit_retention_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_retention_configure_audit_score == "true" ]]; then
        ask 'audit_retention_configure - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/^expire-after.*/expire-after:60d OR 5G/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: audit_retention_configure ..."
            /usr/bin/sed -i.bak 's/^expire-after.*/expire-after:60d OR 5G/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        logmessage "Settings for: audit_retention_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "audit_retention_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
echo "$(date -u) Remediation complete" >> "$audit_log"

} 2>/dev/null

# Usage instructions and initialization
usage=(
    "$0 Usage"
    "$0 [--check] [--fix] [--cfc] [--stats] [--compliant] [--non_compliant] [--reset] [--reset-all] [--quiet=<value>] [--loop]"
    " "
    "Optional parameters:"
    "--check            :   run the compliance checks without interaction"
    "--fix              :   run the remediation commands without interation"
    "--cfc              :   runs a check, fix, check without interaction"
    "--stats            :   display the statistics from last compliance check"
    "--compliant        :   reports the number of compliant checks"
    "--non_compliant    :   reports the number of non_compliant checks"
    "--reset            :   clear out all results for current baseline"
    "--reset-all        :   clear out all results for ALL MSCP baselines"
    "--quiet=<value>    :   1 - show only failed and exempted checks in output"
    "                       2 - show minimal output"
    "--loop             :   continuously run the menu loop even after actions"
  )

# Parse options and handle invalid inputs
zparseopts -D -E -help=flag_help -check=check -fix=fix -stats=stats -compliant=compliant_opt -non_compliant=non_compliant_opt -reset=reset -reset-all=reset_all -cfc=cfc -quiet:=quiet -loop=loop || { print -l $usage && return }

[[ -z "$flag_help" ]] || { print -l $usage && return }

if [[ ! -z $quiet ]]; then
  [[ ! -z ${quiet[2][2]} ]] || { print -l $usage && return }
fi

# Reset handling
if [[ $reset ]] || [[ $reset_all ]]; then 
    reset_plist
fi

# Operations based on flags with debug output
if [[ $check ]] || [[ $fix ]] || [[ $cfc ]] || [[ $stats ]] || [[ $compliant_opt ]] || [[ $non_compliant_opt ]]; then
    echo "Running operations based on flags..."
    [[ $fix ]] && { echo "Running fix..."; run_fix; }
    [[ $check ]] && { echo "Running check..."; run_scan; }
    [[ $cfc ]] && { echo "Running check, fix, check..."; run_scan; run_fix; run_scan; }
    [[ $stats ]] && { echo "Generating stats..."; generate_stats; }
    [[ $compliant_opt ]] && { echo "Counting compliant..."; compliance_count "compliant"; }
    [[ $non_compliant_opt ]] && { echo "Counting non-compliant..."; compliance_count "non-compliant"; }
    echo "Operations complete. Exiting."
    exit 0
fi

# Conditional looping based on explicit user input
if [[ -z $loop ]]; then
    echo "No looping flag set. Running menu once and exiting."
    show_menus
    read_options
    exit 0
else
    echo "Loop flag is set. Entering interactive menu loop."
    while true; do
        show_menus
        read_options
    done
fi

# Exit script explicitly
exit 0