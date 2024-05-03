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

audit_plist="/Library/Preferences/org.systemsettingsrules.audit.plist"
audit_log="/Library/Logs/systemsettingsrules_baseline.log"

# pause function
pause(){
vared -p "Press [Enter] key to continue..." -c fackEnterKey
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

ask() {
    # if fix flag is passed, assume YES for everything
    if [[ $fix ]] || [[ $cfc ]]; then
        return 0
    fi

    while true; do

        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        # Ask the question - use /dev/tty in case stdin is redirected from somewhere else
        printf "${YELLOW} $1 [$prompt] ${STD}"
        read REPLY

        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac

    done
}

# function to display menus
show_menus() {
    lastComplianceScan=$(defaults read /Library/Preferences/org.systemsettingsrules.audit.plist lastComplianceCheck)

    if [[ $lastComplianceScan == "" ]];then
        lastComplianceScan="No scans have been run"
    fi

    /usr/bin/clear
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "        M A I N - M E N U"
    echo "  macOS Security Compliance Tool"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "Last compliance scan: $lastComplianceScan
"
    echo "1. View Last Compliance Report"
    echo "2. Run New Compliance Scan"
    echo "3. Run Commands to remediate non-compliant settings"
    echo "4. Exit"
}

# function to read options
read_options(){
    local choice
    vared -p "Enter choice [ 1 - 4 ] " -c choice
    case $choice in
        1) view_report ;;
        2) run_scan ;;
        3) run_fix ;;
        4) exit 0;;
        *) echo -e "${RED}Error: please choose an option 1-4...${STD}" && sleep 1
    esac
}

# function to reset and remove plist file.  Used to clear out any previous findings
reset_plist(){
    if [[ $reset_all ]];then
        echo "Clearing results from all MSCP baselines"
        find /Library/Preferences -name "org.*.audit.plist" -exec rm -f '{}' \;
        find /Library/Logs -name "*_baseline.log" -exec rm -f '{}' \;
    else
        echo "Clearing results from /Library/Preferences/org.systemsettingsrules.audit.plist"
        rm -f /Library/Preferences/org.systemsettingsrules.audit.plist
        rm -f /Library/Logs/systemsettingsrules_baseline.log
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
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey("$rule"))["exempt"]
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
 	echo "$(date -u) Beginning systemsettingsrules baseline scan" >> "$audit_log"
else
 	echo "$(date -u) Beginning systemsettingsrules baseline scan" > "$audit_log"
fi

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
/usr/bin/defaults write "$audit_plist" lastComplianceCheck "$(date)"
    
#####----- Rule: system_settings_airplay_receiver_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirPlayIncomingRequests').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_airplay_receiver_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_airplay_receiver_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_airplay_receiver_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "false" ]]; then
        logmessage "system_settings_airplay_receiver_disable passed (Result: $result_value, Expected: \"{'string': 'false'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_airplay_receiver_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_airplay_receiver_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_airplay_receiver_disable failed (Result: $result_value, Expected: \"{'string': 'false'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_airplay_receiver_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_airplay_receiver_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            logmessage "system_settings_airplay_receiver_disable failed (Result: $result_value, Expected: \"{'string': 'false'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_airplay_receiver_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_airplay_receiver_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_airplay_receiver_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_airplay_receiver_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_automatic_login_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2
# * IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_automatic_login_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_automatic_login_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_automatic_login_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_automatic_login_disable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_automatic_login_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_automatic_login_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_automatic_login_disable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_automatic_login_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_automatic_login_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_automatic_login_disable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_automatic_login_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_automatic_login_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_automatic_login_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_automatic_login_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_bluetooth_menu_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter')\
.objectForKey('Bluetooth').js
EOS
)
    # expected result {'integer': 18}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_bluetooth_menu_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_bluetooth_menu_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_bluetooth_menu_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "18" ]]; then
        logmessage "system_settings_bluetooth_menu_enable passed (Result: $result_value, Expected: \"{'integer': 18}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_bluetooth_menu_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_bluetooth_menu_enable passed (Result: $result_value, Expected: "{'integer': 18}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_bluetooth_menu_enable failed (Result: $result_value, Expected: \"{'integer': 18}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_bluetooth_menu_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_bluetooth_menu_enable failed (Result: $result_value, Expected: "{'integer': 18}")"
        else
            logmessage "system_settings_bluetooth_menu_enable failed (Result: $result_value, Expected: \"{'integer': 18}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_bluetooth_menu_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_bluetooth_menu_enable failed (Result: $result_value, Expected: "{'integer': 18}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_bluetooth_menu_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_menu_enable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18(4)
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_bluetooth_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_bluetooth_sharing_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_bluetooth_sharing_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "system_settings_bluetooth_sharing_disable passed (Result: $result_value, Expected: \"{'boolean': 0}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_bluetooth_sharing_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_bluetooth_sharing_disable passed (Result: $result_value, Expected: "{'boolean': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_bluetooth_sharing_disable failed (Result: $result_value, Expected: \"{'boolean': 0}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_bluetooth_sharing_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}")"
        else
            logmessage "system_settings_bluetooth_sharing_disable failed (Result: $result_value, Expected: \"{'boolean': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_bluetooth_sharing_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_bluetooth_sharing_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_bluetooth_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_cd_dvd_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/pgrep -q ODSAgent; /bin/echo $?
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_cd_dvd_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_cd_dvd_sharing_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_cd_dvd_sharing_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_cd_dvd_sharing_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_cd_dvd_sharing_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_cd_dvd_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_cd_dvd_sharing_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_cd_dvd_sharing_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_cd_dvd_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_cd_dvd_sharing_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_cd_dvd_sharing_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_cd_dvd_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_cd_dvd_sharing_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_cd_dvd_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_critical_update_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('CriticalUpdateInstall').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_critical_update_install_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_critical_update_install_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_critical_update_install_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_critical_update_install_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_critical_update_install_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_critical_update_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_critical_update_install_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_critical_update_install_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_critical_update_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_critical_update_install_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_critical_update_install_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_critical_update_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_critical_update_install_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_critical_update_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_filevault_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-28, SC-28(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(dontAllowDisable=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('dontAllowFDEDisable').js
EOS
)
fileVault=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
if [[ "$dontAllowDisable" == "true" ]] && [[ "$fileVault" == 1 ]]; then
  echo "1"
else
  echo "0"
fi
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_filevault_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_filevault_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_filevault_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_filevault_enforce passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_filevault_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_filevault_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_filevault_enforce failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_filevault_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_filevault_enforce failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_filevault_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_filevault_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_filevault_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(profile="$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableFirewall').js
EOS
)"

plist="$(/usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)"

if [[ "$profile" == "true" ]] && [[ "$plist" =~ [1,2] ]]; then
  echo "true"
else
  echo "false"
fi
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_firewall_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_firewall_enable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_firewall_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_firewall_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_firewall_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_firewall_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_firewall_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_firewall_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_firewall_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_firewall_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_firewall_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_firewall_enable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(profile="$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableStealthMode').js
EOS
)"

plist=$(/usr/bin/defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)

if [[ "$profile" == "true" ]] && [[ $plist == 1 ]]; then
  echo "true"
else
  echo "false"
fi
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_firewall_stealth_mode_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_firewall_stealth_mode_enable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_firewall_stealth_mode_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_firewall_stealth_mode_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_firewall_stealth_mode_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_firewall_stealth_mode_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_firewall_stealth_mode_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_firewall_stealth_mode_enable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess
)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_guest_access_smb_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_guest_access_smb_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_guest_access_smb_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "system_settings_guest_access_smb_disable passed (Result: $result_value, Expected: \"{'boolean': 0}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_guest_access_smb_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_guest_access_smb_disable passed (Result: $result_value, Expected: "{'boolean': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_guest_access_smb_disable failed (Result: $result_value, Expected: \"{'boolean': 0}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_guest_access_smb_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}")"
        else
            logmessage "system_settings_guest_access_smb_disable failed (Result: $result_value, Expected: \"{'boolean': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_guest_access_smb_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_guest_access_smb_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_guest_access_smb_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_guest_account_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('DisableGuestAccount'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('EnableGuestAccount'))
  if ( pref1 == true && pref2 == false ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_guest_account_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_guest_account_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_guest_account_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_guest_account_disable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_guest_account_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_guest_account_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_guest_account_disable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_guest_account_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_guest_account_disable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_guest_account_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_guest_account_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_guest_account_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_install_macos_updates_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticallyInstallMacOSUpdates').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_install_macos_updates_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_install_macos_updates_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_install_macos_updates_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_install_macos_updates_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_install_macos_updates_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_install_macos_updates_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_install_macos_updates_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_install_macos_updates_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_install_macos_updates_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_install_macos_updates_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_install_macos_updates_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_install_macos_updates_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_install_macos_updates_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_install_macos_updates_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_internet_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_internet_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_internet_sharing_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_internet_sharing_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_internet_sharing_disable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_internet_sharing_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_internet_sharing_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_internet_sharing_disable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_internet_sharing_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_internet_sharing_disable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_internet_sharing_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_internet_sharing_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_internet_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_loginwindow_loginwindowtext_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS | /usr/bin/base64
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('LoginwindowText').js
EOS
)
    # expected result base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_loginwindow_loginwindowtext_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_loginwindow_loginwindowtext_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_loginwindow_loginwindowtext_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "Q2VudGVyIGZvciBJbnRlcm5ldCBTZWN1cml0eSBUZXN0IE1lc3NhZ2UK" ]]; then
        logmessage "system_settings_loginwindow_loginwindowtext_enable passed (Result: $result_value, Expected: \"base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk\")"
        /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_loginwindow_loginwindowtext_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_loginwindow_loginwindowtext_enable passed (Result: $result_value, Expected: "base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_loginwindow_loginwindowtext_enable failed (Result: $result_value, Expected: \"base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk\")"
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_loginwindow_loginwindowtext_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_loginwindow_loginwindowtext_enable failed (Result: $result_value, Expected: "base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk")"
        else
            logmessage "system_settings_loginwindow_loginwindowtext_enable failed (Result: $result_value, Expected: \"base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_loginwindow_loginwindowtext_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_loginwindow_loginwindowtext_enable failed (Result: $result_value, Expected: "base64: q2vudgvyigzvcibjbnrlcm5ldcbtzwn1cml0esbuzxn0ie1lc3nhz2uk") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_loginwindow_loginwindowtext_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_loginwindowtext_enable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_loginwindow_prompt_username_password_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_loginwindow_prompt_username_password_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_loginwindow_prompt_username_password_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_loginwindow_prompt_username_password_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_loginwindow_prompt_username_password_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_loginwindow_prompt_username_password_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_loginwindow_prompt_username_password_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_loginwindow_prompt_username_password_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_loginwindow_prompt_username_password_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_loginwindow_prompt_username_password_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_loginwindow_prompt_username_password_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_loginwindow_prompt_username_password_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_password_hints_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_password_hints_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_password_hints_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_password_hints_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "system_settings_password_hints_disable passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_password_hints_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_password_hints_disable passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_password_hints_disable failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_password_hints_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "system_settings_password_hints_disable failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_password_hints_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_password_hints_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_password_hints_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_password_hints_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_personalized_advertising_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowApplePersonalizedAdvertising').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_personalized_advertising_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_personalized_advertising_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_personalized_advertising_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "false" ]]; then
        logmessage "system_settings_personalized_advertising_disable passed (Result: $result_value, Expected: \"{'string': 'false'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_personalized_advertising_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_personalized_advertising_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_personalized_advertising_disable failed (Result: $result_value, Expected: \"{'string': 'false'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_personalized_advertising_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_personalized_advertising_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            logmessage "system_settings_personalized_advertising_disable failed (Result: $result_value, Expected: \"{'string': 'false'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_personalized_advertising_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_personalized_advertising_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_personalized_advertising_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_personalized_advertising_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_printer_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/sbin/cupsctl | /usr/bin/grep -c "_share_printers=0"
)
    # expected result {'boolean': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_printer_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_printer_sharing_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_printer_sharing_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_printer_sharing_disable passed (Result: $result_value, Expected: \"{'boolean': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_printer_sharing_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_printer_sharing_disable passed (Result: $result_value, Expected: "{'boolean': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_printer_sharing_disable failed (Result: $result_value, Expected: \"{'boolean': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_printer_sharing_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_printer_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 1}")"
        else
            logmessage "system_settings_printer_sharing_disable failed (Result: $result_value, Expected: \"{'boolean': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_printer_sharing_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_printer_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_printer_sharing_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_printer_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_rae_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_rae_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_rae_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_rae_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_rae_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_rae_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_rae_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_rae_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_rae_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_rae_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_rae_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_rae_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_remote_management_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "RemoteDesktopEnabled = 0"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_remote_management_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_remote_management_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_remote_management_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_remote_management_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_remote_management_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_remote_management_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_remote_management_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_remote_management_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_remote_management_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_remote_management_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_remote_management_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_remote_management_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_remote_management_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_remote_management_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_screen_sharing_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_screen_sharing_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_screen_sharing_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screen_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_screen_sharing_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_screen_sharing_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_screen_sharing_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_screen_sharing_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_screen_sharing_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_screen_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screensaver_ask_for_password_delay_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPasswordDelay'))
  if ( delay <= 5 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screensaver_ask_for_password_delay_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screensaver_ask_for_password_delay_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_screensaver_ask_for_password_delay_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_screensaver_ask_for_password_delay_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_screensaver_ask_for_password_delay_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screensaver_ask_for_password_delay_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_screensaver_ask_for_password_delay_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_screensaver_ask_for_password_delay_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screensaver_ask_for_password_delay_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_screensaver_ask_for_password_delay_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_screensaver_ask_for_password_delay_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_screensaver_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime'))
  if ( timeout <= 1200 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screensaver_timeout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screensaver_timeout_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_screensaver_timeout_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_screensaver_timeout_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_screensaver_timeout_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screensaver_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_screensaver_timeout_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_screensaver_timeout_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_screensaver_timeout_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_screensaver_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_smbd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_smbd_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_smbd_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_smbd_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_smbd_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_smbd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_smbd_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_smbd_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_smbd_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_smbd_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_smbd_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_smbd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_software_update_app_update_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticallyInstallAppUpdates').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_software_update_app_update_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_software_update_app_update_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_software_update_app_update_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_software_update_app_update_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_software_update_app_update_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_app_update_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_software_update_app_update_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_software_update_app_update_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_app_update_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_software_update_app_update_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_software_update_app_update_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_app_update_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_software_update_app_update_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_software_update_app_update_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_software_update_download_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticDownload').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_software_update_download_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_software_update_download_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_software_update_download_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_software_update_download_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_software_update_download_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_download_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_software_update_download_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_software_update_download_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_download_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_software_update_download_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_software_update_download_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_download_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_software_update_download_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_software_update_download_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_software_update_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticCheckEnabled').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_software_update_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_software_update_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_software_update_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_software_update_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_software_update_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_software_update_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_software_update_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_software_update_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_software_update_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_software_update_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_software_update_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_software_update_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_softwareupdate_current -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(softwareupdate_date_epoch=$(/bin/date -j -f "%Y-%m-%d" "$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastFullSuccessfulDate | /usr/bin/awk '{print $1}')" "+%s")
thirty_days_epoch=$(/bin/date -v -30d "+%s")
if [[ $softwareupdate_date_epoch -lt $thirty_days_epoch ]]; then
  /bin/echo "0"
else
  /bin/echo "1"
fi
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_softwareupdate_current'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_softwareupdate_current'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_softwareupdate_current" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_softwareupdate_current passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_softwareupdate_current" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_softwareupdate_current passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_softwareupdate_current failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_softwareupdate_current" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_softwareupdate_current failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_softwareupdate_current failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_softwareupdate_current" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_softwareupdate_current failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_softwareupdate_current does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_softwareupdate_current -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_ssh_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_ssh_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_ssh_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_ssh_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_ssh_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_ssh_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_ssh_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_ssh_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_ssh_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_ssh_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_ssh_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_ssh_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_ssh_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_ssh_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_ssh_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6, AC-6(1), AC-6(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
result="1"
for section in ${authDBs[@]}; do
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
  if [[ $(security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath '//*[contains(text(), "group")]/following-sibling::*[1]/text()' - ) != "admin" ]]; then
    result="0"
  fi
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "authenticate-user")]/following-sibling::*[1])' -) != "true" ]]; then
    result="0"
  fi
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "session-owner")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
done
echo $result
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_system_wide_preferences_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "system_settings_system_wide_preferences_configure passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_system_wide_preferences_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_system_wide_preferences_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_system_wide_preferences_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_system_wide_preferences_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_system_wide_preferences_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_system_wide_preferences_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_system_wide_preferences_configure -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_time_machine_encrypted_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(error_count=0
for tm in $(/usr/bin/tmutil destinationinfo 2>/dev/null| /usr/bin/awk -F': ' '/Name/{print $2}'); do
  tmMounted=$(/usr/sbin/diskutil info "${tm}" 2>/dev/null | /usr/bin/awk '/Mounted/{print $2}')
  tmEncrypted=$(/usr/sbin/diskutil info "${tm}" 2>/dev/null | /usr/bin/awk '/FileVault/{print $2}')
  if [[ "$tmMounted" = "Yes" && "$tmEncrypted" = "No" ]]; then
      ((error_count++))
  fi
done
echo "$error_count"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_time_machine_encrypted_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_time_machine_encrypted_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_time_machine_encrypted_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "system_settings_time_machine_encrypted_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_time_machine_encrypted_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_machine_encrypted_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_time_machine_encrypted_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_time_machine_encrypted_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_machine_encrypted_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "system_settings_time_machine_encrypted_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_time_machine_encrypted_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_machine_encrypted_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_time_machine_encrypted_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_time_machine_encrypted_configure -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_time_server_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS
)
    # expected result {'string': 'time.apple.com'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_time_server_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_time_server_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_time_server_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "time.apple.com" ]]; then
        logmessage "system_settings_time_server_configure passed (Result: $result_value, Expected: \"{'string': 'time.apple.com'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_time_server_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_server_configure passed (Result: $result_value, Expected: "{'string': 'time.apple.com'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_time_server_configure failed (Result: $result_value, Expected: \"{'string': 'time.apple.com'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_time_server_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time.apple.com'}")"
        else
            logmessage "system_settings_time_server_configure failed (Result: $result_value, Expected: \"{'string': 'time.apple.com'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_time_server_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time.apple.com'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_time_server_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_time_server_configure -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_time_server_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_time_server_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_time_server_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_time_server_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "system_settings_time_server_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_time_server_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_server_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_time_server_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_time_server_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "system_settings_time_server_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_time_server_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_time_server_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_time_server_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_wake_network_access_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/pmset -g custom | /usr/bin/awk '/womp/ { sum+=$2 } END {print sum}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_wake_network_access_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_wake_network_access_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_wake_network_access_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "system_settings_wake_network_access_disable passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_wake_network_access_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_wake_network_access_disable passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_wake_network_access_disable failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_wake_network_access_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_wake_network_access_disable failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "system_settings_wake_network_access_disable failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_wake_network_access_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_wake_network_access_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_wake_network_access_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_wake_network_access_disable -dict-add finding -bool NO
fi
    
#####----- Rule: system_settings_wifi_menu_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter')\
.objectForKey('WiFi').js
EOS
)
    # expected result {'integer': 18}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_wifi_menu_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_wifi_menu_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "system_settings_wifi_menu_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "18" ]]; then
        logmessage "system_settings_wifi_menu_enable passed (Result: $result_value, Expected: \"{'integer': 18}\")"
        /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "system_settings_wifi_menu_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: systemsettingsrules - system_settings_wifi_menu_enable passed (Result: $result_value, Expected: "{'integer': 18}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "system_settings_wifi_menu_enable failed (Result: $result_value, Expected: \"{'integer': 18}\")"
            /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_wifi_menu_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_wifi_menu_enable failed (Result: $result_value, Expected: "{'integer': 18}")"
        else
            logmessage "system_settings_wifi_menu_enable failed (Result: $result_value, Expected: \"{'integer': 18}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "system_settings_wifi_menu_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: systemsettingsrules - system_settings_wifi_menu_enable failed (Result: $result_value, Expected: "{'integer': 18}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "system_settings_wifi_menu_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" system_settings_wifi_menu_enable -dict-add finding -bool NO
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


    
#####----- Rule: system_settings_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18(4)
# * AC-3
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_bluetooth_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_bluetooth_sharing_disable'))["exempt_reason"]
EOS
)

system_settings_bluetooth_sharing_disable_audit_score=$($plb -c "print system_settings_bluetooth_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_bluetooth_sharing_disable_audit_score == "true" ]]; then
        ask 'system_settings_bluetooth_sharing_disable - Run the command(s)-> /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_bluetooth_sharing_disable ..."
            /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
        fi
    else
        logmessage "Settings for: system_settings_bluetooth_sharing_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_bluetooth_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_cd_dvd_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_cd_dvd_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_cd_dvd_sharing_disable'))["exempt_reason"]
EOS
)

system_settings_cd_dvd_sharing_disable_audit_score=$($plb -c "print system_settings_cd_dvd_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_cd_dvd_sharing_disable_audit_score == "true" ]]; then
        ask 'system_settings_cd_dvd_sharing_disable - Run the command(s)-> /bin/launchctl unload /System/Library/LaunchDaemons/com.apple.ODSAgent.plist ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_cd_dvd_sharing_disable ..."
            /bin/launchctl unload /System/Library/LaunchDaemons/com.apple.ODSAgent.plist
        fi
    else
        logmessage "Settings for: system_settings_cd_dvd_sharing_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_cd_dvd_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_enable'))["exempt_reason"]
EOS
)

system_settings_firewall_enable_audit_score=$($plb -c "print system_settings_firewall_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_firewall_enable_audit_score == "true" ]]; then
        ask 'system_settings_firewall_enable - Run the command(s)-> /usr/bin/defaults write /Library/Preferences/com.apple.alf globalstate -int 1 ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_firewall_enable ..."
            /usr/bin/defaults write /Library/Preferences/com.apple.alf globalstate -int 1
        fi
    else
        logmessage "Settings for: system_settings_firewall_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_firewall_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_firewall_stealth_mode_enable'))["exempt_reason"]
EOS
)

system_settings_firewall_stealth_mode_enable_audit_score=$($plb -c "print system_settings_firewall_stealth_mode_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_firewall_stealth_mode_enable_audit_score == "true" ]]; then
        ask 'system_settings_firewall_stealth_mode_enable - Run the command(s)-> /usr/bin/defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1 ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_firewall_stealth_mode_enable ..."
            /usr/bin/defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1
        fi
    else
        logmessage "Settings for: system_settings_firewall_stealth_mode_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_firewall_stealth_mode_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_guest_access_smb_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_guest_access_smb_disable'))["exempt_reason"]
EOS
)

system_settings_guest_access_smb_disable_audit_score=$($plb -c "print system_settings_guest_access_smb_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_guest_access_smb_disable_audit_score == "true" ]]; then
        ask 'system_settings_guest_access_smb_disable - Run the command(s)-> /usr/sbin/sysadminctl -smbGuestAccess off ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_guest_access_smb_disable ..."
            /usr/sbin/sysadminctl -smbGuestAccess off
        fi
    else
        logmessage "Settings for: system_settings_guest_access_smb_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_guest_access_smb_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_printer_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_printer_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_printer_sharing_disable'))["exempt_reason"]
EOS
)

system_settings_printer_sharing_disable_audit_score=$($plb -c "print system_settings_printer_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_printer_sharing_disable_audit_score == "true" ]]; then
        ask 'system_settings_printer_sharing_disable - Run the command(s)-> /usr/sbin/cupsctl --no-share-printers
/usr/bin/lpstat -p | awk '"'"'{print $2}'"'"'| /usr/bin/xargs -I{} lpadmin -p {} -o printer-is-shared=false ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_printer_sharing_disable ..."
            /usr/sbin/cupsctl --no-share-printers
/usr/bin/lpstat -p | awk '{print $2}'| /usr/bin/xargs -I{} lpadmin -p {} -o printer-is-shared=false
        fi
    else
        logmessage "Settings for: system_settings_printer_sharing_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_printer_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_rae_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_rae_disable'))["exempt_reason"]
EOS
)

system_settings_rae_disable_audit_score=$($plb -c "print system_settings_rae_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_rae_disable_audit_score == "true" ]]; then
        ask 'system_settings_rae_disable - Run the command(s)-> /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_rae_disable ..."
            /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer
        fi
    else
        logmessage "Settings for: system_settings_rae_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_rae_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_remote_management_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_remote_management_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_remote_management_disable'))["exempt_reason"]
EOS
)

system_settings_remote_management_disable_audit_score=$($plb -c "print system_settings_remote_management_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_remote_management_disable_audit_score == "true" ]]; then
        ask 'system_settings_remote_management_disable - Run the command(s)-> /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_remote_management_disable ..."
            /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
        fi
    else
        logmessage "Settings for: system_settings_remote_management_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_remote_management_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_screen_sharing_disable'))["exempt_reason"]
EOS
)

system_settings_screen_sharing_disable_audit_score=$($plb -c "print system_settings_screen_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_screen_sharing_disable_audit_score == "true" ]]; then
        ask 'system_settings_screen_sharing_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.screensharing ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_screen_sharing_disable ..."
            /bin/launchctl disable system/com.apple.screensharing
        fi
    else
        logmessage "Settings for: system_settings_screen_sharing_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_screen_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_smbd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_smbd_disable'))["exempt_reason"]
EOS
)

system_settings_smbd_disable_audit_score=$($plb -c "print system_settings_smbd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_smbd_disable_audit_score == "true" ]]; then
        ask 'system_settings_smbd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.smbd ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_smbd_disable ..."
            /bin/launchctl disable system/com.apple.smbd
        fi
    else
        logmessage "Settings for: system_settings_smbd_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_smbd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_softwareupdate_current -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_softwareupdate_current'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_softwareupdate_current'))["exempt_reason"]
EOS
)

system_settings_softwareupdate_current_audit_score=$($plb -c "print system_settings_softwareupdate_current:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_softwareupdate_current_audit_score == "true" ]]; then
        ask 'system_settings_softwareupdate_current - Run the command(s)-> /usr/sbin/softwareupdate -i -a ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_softwareupdate_current ..."
            /usr/sbin/softwareupdate -i -a
        fi
    else
        logmessage "Settings for: system_settings_softwareupdate_current already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_softwareupdate_current has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_ssh_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_ssh_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_ssh_disable'))["exempt_reason"]
EOS
)

system_settings_ssh_disable_audit_score=$($plb -c "print system_settings_ssh_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_ssh_disable_audit_score == "true" ]]; then
        ask 'system_settings_ssh_disable - Run the command(s)-> /usr/sbin/systemsetup -f -setremotelogin off >/dev/null
/bin/launchctl disable system/com.openssh.sshd ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_ssh_disable ..."
            /usr/sbin/systemsetup -f -setremotelogin off >/dev/null
/bin/launchctl disable system/com.openssh.sshd
        fi
    else
        logmessage "Settings for: system_settings_ssh_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_ssh_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_system_wide_preferences_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6, AC-6(1), AC-6(2)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_system_wide_preferences_configure'))["exempt_reason"]
EOS
)

system_settings_system_wide_preferences_configure_audit_score=$($plb -c "print system_settings_system_wide_preferences_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_system_wide_preferences_configure_audit_score == "true" ]]; then
        ask 'system_settings_system_wide_preferences_configure - Run the command(s)-> authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")

for section in ${authDBs[@]}; do
  /usr/bin/security -q authorizationdb read "$section" > "/tmp/$section.plist"

  class_key_value=$(usr/libexec/PlistBuddy -c "Print :class" "/tmp/$section.plist" 2>&1)
  if [[ "$class_key_value" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :class string user" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :class user" "/tmp/$section.plist"
  fi

  key_value=$(/usr/libexec/PlistBuddy -c "Print :shared" "/tmp/$section.plist" 2>&1)  	
  if [[ "$key_value" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :shared bool false" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :shared false" "/tmp/$section.plist"
  fi

  auth_user_key=$(/usr/libexec/PlistBuddy -c "Print :authenticate-user" "/tmp/$section.plist" 2>&1)  	
  if [[ "$auth_user_key" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :authenticate-user bool true" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :authenticate-user true" "/tmp/$section.plist"
  fi

  session_owner_key=$(/usr/libexec/PlistBuddy -c "Print :session-owner" "/tmp/$section.plist" 2>&1)  	
  if [[ "$session_owner_key" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :session-owner bool false" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :session-owner false" "/tmp/$section.plist"
  fi

  group_key=$(usr/libexec/PlistBuddy -c "Print :group" "/tmp/$section.plist" 2>&1)
  if [[ "$group_key" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :group string admin" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :group admin" "/tmp/$section.plist"
  fi

  /usr/bin/security -q authorizationdb write "$section" < "/tmp/$section.plist"
done ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_system_wide_preferences_configure ..."
            authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")

for section in ${authDBs[@]}; do
  /usr/bin/security -q authorizationdb read "$section" > "/tmp/$section.plist"

  class_key_value=$(usr/libexec/PlistBuddy -c "Print :class" "/tmp/$section.plist" 2>&1)
  if [[ "$class_key_value" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :class string user" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :class user" "/tmp/$section.plist"
  fi

  key_value=$(/usr/libexec/PlistBuddy -c "Print :shared" "/tmp/$section.plist" 2>&1)  	
  if [[ "$key_value" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :shared bool false" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :shared false" "/tmp/$section.plist"
  fi

  auth_user_key=$(/usr/libexec/PlistBuddy -c "Print :authenticate-user" "/tmp/$section.plist" 2>&1)  	
  if [[ "$auth_user_key" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :authenticate-user bool true" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :authenticate-user true" "/tmp/$section.plist"
  fi

  session_owner_key=$(/usr/libexec/PlistBuddy -c "Print :session-owner" "/tmp/$section.plist" 2>&1)  	
  if [[ "$session_owner_key" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :session-owner bool false" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :session-owner false" "/tmp/$section.plist"
  fi

  group_key=$(usr/libexec/PlistBuddy -c "Print :group" "/tmp/$section.plist" 2>&1)
  if [[ "$group_key" == *"Does Not Exist"* ]]; then
    /usr/libexec/PlistBuddy -c "Add :group string admin" "/tmp/$section.plist"
  else
    /usr/libexec/PlistBuddy -c "Set :group admin" "/tmp/$section.plist"
  fi

  /usr/bin/security -q authorizationdb write "$section" < "/tmp/$section.plist"
done
        fi
    else
        logmessage "Settings for: system_settings_system_wide_preferences_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_system_wide_preferences_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: system_settings_wake_network_access_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_wake_network_access_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.systemsettingsrules.audit').objectForKey('system_settings_wake_network_access_disable'))["exempt_reason"]
EOS
)

system_settings_wake_network_access_disable_audit_score=$($plb -c "print system_settings_wake_network_access_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $system_settings_wake_network_access_disable_audit_score == "true" ]]; then
        ask 'system_settings_wake_network_access_disable - Run the command(s)-> /usr/bin/pmset -a womp 0 ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: system_settings_wake_network_access_disable ..."
            /usr/bin/pmset -a womp 0
        fi
    else
        logmessage "Settings for: system_settings_wake_network_access_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "system_settings_wake_network_access_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
echo "$(date -u) Remediation complete" >> "$audit_log"

} 2>/dev/null

usage=(
    "$0 Usage"
    "$0 [--check] [--fix] [--cfc] [--stats] [--compliant] [--non_compliant] [--reset] [--reset-all] [--quiet=<value>]"
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
  )

zparseopts -D -E -help=flag_help -check=check -fix=fix -stats=stats -compliant=compliant_opt -non_compliant=non_compliant_opt -reset=reset -reset-all=reset_all -cfc=cfc -quiet:=quiet || { print -l $usage && return }

[[ -z "$flag_help" ]] || { print -l $usage && return }

if [[ ! -z $quiet ]];then
  [[ ! -z ${quiet[2][2]} ]] || { print -l $usage && return }
fi

if [[ $reset ]] || [[ $reset_all ]]; then reset_plist; fi

if [[ $check ]] || [[ $fix ]] || [[ $cfc ]] || [[ $stats ]] || [[ $compliant_opt ]] || [[ $non_compliant_opt ]]; then
    if [[ $fix ]]; then run_fix; fi
    if [[ $check ]]; then run_scan; fi
    if [[ $cfc ]]; then run_scan; run_fix; run_scan; fi
    if [[ $stats ]];then generate_stats; fi
    if [[ $compliant_opt ]];then compliance_count "compliant"; fi
    if [[ $non_compliant_opt ]];then compliance_count "non-compliant"; fi
else
    while true; do
        show_menus
        read_options
    done
fi

if [[ "$ssh_key_check" -ne 0 ]]; then
    /bin/rm /etc/ssh/ssh_host_rsa_key
    /bin/rm /etc/ssh/ssh_host_rsa_key.pub
    ssh_key_check=0
fi
    