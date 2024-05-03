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

audit_plist="/Library/Preferences/org.macosrules.audit.plist"
audit_log="/Library/Logs/macosrules_baseline.log"

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
    lastComplianceScan=$(defaults read /Library/Preferences/org.macosrules.audit.plist lastComplianceCheck)

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
        echo "Clearing results from /Library/Preferences/org.macosrules.audit.plist"
        rm -f /Library/Preferences/org.macosrules.audit.plist
        rm -f /Library/Logs/macosrules_baseline.log
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
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey("$rule"))["exempt"]
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
 	echo "$(date -u) Beginning macosrules baseline scan" >> "$audit_log"
else
 	echo "$(date -u) Beginning macosrules baseline scan" > "$audit_log"
fi

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
/usr/bin/defaults write "$audit_plist" lastComplianceCheck "$(date)"
    
#####----- Rule: os_airdrop_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_airdrop_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_airdrop_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_airdrop_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "false" ]]; then
        logmessage "os_airdrop_disable passed (Result: $result_value, Expected: \"{'string': 'false'}\")"
        /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_airdrop_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_airdrop_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_airdrop_disable failed (Result: $result_value, Expected: \"{'string': 'false'}\")"
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_airdrop_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            logmessage "os_airdrop_disable failed (Result: $result_value, Expected: \"{'string': 'false'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_airdrop_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_airdrop_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_anti_virus_installed -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -cE "(com.apple.XprotectFramework.PluginService$|com.apple.XProtect.daemon.scan$)"
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_anti_virus_installed'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_anti_virus_installed'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_anti_virus_installed" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "2" ]]; then
        logmessage "os_anti_virus_installed passed (Result: $result_value, Expected: \"{'integer': 2}\")"
        /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool NO
        if [[ ! "$customref" == "os_anti_virus_installed" ]]; then
            /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_anti_virus_installed passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_anti_virus_installed failed (Result: $result_value, Expected: \"{'integer': 2}\")"
            /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool YES
            if [[ ! "$customref" == "os_anti_virus_installed" ]]; then
                /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_anti_virus_installed failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            logmessage "os_anti_virus_installed failed (Result: $result_value, Expected: \"{'integer': 2}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool YES
            if [[ ! "$customref" == "os_anti_virus_installed" ]]; then
              /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_anti_virus_installed failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_anti_virus_installed does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_anti_virus_installed -dict-add finding -bool NO
fi
    
#####----- Rule: os_authenticated_root_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * CM-5
# * MA-4(1)
# * SC-34
# * SI-7, SI-7(6)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_authenticated_root_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_authenticated_root_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_authenticated_root_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_authenticated_root_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_authenticated_root_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_authenticated_root_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_authenticated_root_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_authenticated_root_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_authenticated_root_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_authenticated_root_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_authenticated_root_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_authenticated_root_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_authenticated_root_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_authenticated_root_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_config_data_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2(5)
# * SI-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_config_data_install_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_config_data_install_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_config_data_install_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "os_config_data_install_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "os_config_data_install_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_config_data_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_config_data_install_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "os_config_data_install_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "os_config_data_install_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "os_config_data_install_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_config_data_install_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_firewall_log_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12
# * SC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
  .objectForKey('EnableLogging').js
  let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
  .objectForKey('LoggingOption').js
  if ( pref1 == true && pref2 == "detail" ){
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
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_firewall_log_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_firewall_log_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_firewall_log_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "os_firewall_log_enable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_firewall_log_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_firewall_log_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_firewall_log_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_firewall_log_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_firewall_log_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "os_firewall_log_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_firewall_log_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_firewall_log_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_firewall_log_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_gatekeeper_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_gatekeeper_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_gatekeeper_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_gatekeeper_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_gatekeeper_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_gatekeeper_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_gatekeeper_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_gatekeeper_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_gatekeeper_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_gatekeeper_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_gatekeeper_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_guest_folder_removed -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/ls /Users/ | /usr/bin/grep -c "Guest"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_guest_folder_removed'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_guest_folder_removed'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_guest_folder_removed" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "os_guest_folder_removed passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add finding -bool NO
        if [[ ! "$customref" == "os_guest_folder_removed" ]]; then
            /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_guest_folder_removed passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_guest_folder_removed failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add finding -bool YES
            if [[ ! "$customref" == "os_guest_folder_removed" ]]; then
                /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_guest_folder_removed failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "os_guest_folder_removed failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add finding -bool YES
            if [[ ! "$customref" == "os_guest_folder_removed" ]]; then
              /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_guest_folder_removed failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_guest_folder_removed does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_guest_folder_removed -dict-add finding -bool NO
fi
    
#####----- Rule: os_home_folders_secure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" | /usr/bin/wc -l | /usr/bin/xargs
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_home_folders_secure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_home_folders_secure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_home_folders_secure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "os_home_folders_secure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_home_folders_secure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_home_folders_secure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_home_folders_secure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_home_folders_secure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_home_folders_secure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "os_home_folders_secure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_home_folders_secure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_home_folders_secure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_home_folders_secure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_home_folders_secure -dict-add finding -bool NO
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_httpd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_httpd_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_httpd_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_httpd_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_httpd_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_httpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_httpd_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_httpd_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_httpd_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_httpd_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_httpd_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_install_log_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/sbin/aslmanager -dd 2>&1 | /usr/bin/awk '/\/var\/log\/install.log$/ {count++} /Processing module com.apple.install/,/Finished/ { for (i=1;i<=NR;i++) { if ($i == "TTL" && $(i+2) >= 365) { ttl="True" }; if ($i == "MAX") {max="True"}}} END{if (count > 1) { print "Multiple config files for /var/log/install, manually remove the extra files"} else if (max == "True") { print "all_max setting is configured, must be removed" } if (ttl != "True") { print "TTL not configured" } else { print "Yes" }}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_install_log_retention_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_install_log_retention_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_install_log_retention_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "Yes" ]]; then
        logmessage "os_install_log_retention_configure passed (Result: $result_value, Expected: \"{'string': 'yes'}\")"
        /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_install_log_retention_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_install_log_retention_configure passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_install_log_retention_configure failed (Result: $result_value, Expected: \"{'string': 'yes'}\")"
            /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_install_log_retention_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_install_log_retention_configure failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            logmessage "os_install_log_retention_configure failed (Result: $result_value, Expected: \"{'string': 'yes'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_install_log_retention_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_install_log_retention_configure failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_install_log_retention_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_install_log_retention_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_mdm_require -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-2
# * CM-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_mdm_require'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_mdm_require'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_mdm_require" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_mdm_require passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
        if [[ ! "$customref" == "os_mdm_require" ]]; then
            /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_mdm_require passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_mdm_require failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool YES
            if [[ ! "$customref" == "os_mdm_require" ]]; then
                /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_mdm_require failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool YES
            if [[ ! "$customref" == "os_mdm_require" ]]; then
              /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_mdm_require does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
fi
    
#####----- Rule: os_mobile_file_integrity_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_mobile_file_integrity_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_mobile_file_integrity_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_mobile_file_integrity_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "os_mobile_file_integrity_enable passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_mobile_file_integrity_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_mobile_file_integrity_enable passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_mobile_file_integrity_enable failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_mobile_file_integrity_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_mobile_file_integrity_enable failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "os_mobile_file_integrity_enable failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_mobile_file_integrity_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_mobile_file_integrity_enable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_mobile_file_integrity_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_mobile_file_integrity_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => disabled'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_nfsd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_nfsd_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_nfsd_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_nfsd_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_nfsd_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_nfsd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_nfsd_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_nfsd_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_nfsd_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_nfsd_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_nfsd_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_on_device_dictation_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch="arm64"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('forceOnDeviceOnlyDictation').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_on_device_dictation_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_on_device_dictation_enforce'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_on_device_dictation_enforce" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "os_on_device_dictation_enforce passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add finding -bool NO
        if [[ ! "$customref" == "os_on_device_dictation_enforce" ]]; then
            /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_on_device_dictation_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_on_device_dictation_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "os_on_device_dictation_enforce" ]]; then
                /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_on_device_dictation_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "os_on_device_dictation_enforce failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add finding -bool YES
            if [[ ! "$customref" == "os_on_device_dictation_enforce" ]]; then
              /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_on_device_dictation_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_on_device_dictation_enforce does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_on_device_dictation_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_hint_remove -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(HINT=$(/usr/bin/dscl . -list /Users hint | /usr/bin/awk '{ print $2 }')

if [ -z "$HINT" ]; then
  echo "PASS"
else
  echo "FAIL"
fi
)
    # expected result {'string': 'pass'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_password_hint_remove'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_password_hint_remove'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_password_hint_remove" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "PASS" ]]; then
        logmessage "os_password_hint_remove passed (Result: $result_value, Expected: \"{'string': 'pass'}\")"
        /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add finding -bool NO
        if [[ ! "$customref" == "os_password_hint_remove" ]]; then
            /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_password_hint_remove passed (Result: $result_value, Expected: "{'string': 'pass'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_password_hint_remove failed (Result: $result_value, Expected: \"{'string': 'pass'}\")"
            /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add finding -bool YES
            if [[ ! "$customref" == "os_password_hint_remove" ]]; then
                /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_password_hint_remove failed (Result: $result_value, Expected: "{'string': 'pass'}")"
        else
            logmessage "os_password_hint_remove failed (Result: $result_value, Expected: \"{'string': 'pass'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add finding -bool YES
            if [[ ! "$customref" == "os_password_hint_remove" ]]; then
              /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_password_hint_remove failed (Result: $result_value, Expected: "{'string': 'pass'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_password_hint_remove does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_password_hint_remove -dict-add finding -bool NO
fi
    
#####----- Rule: os_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch="i386"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/pmset -g custom | /usr/bin/awk '/powernap/ { sum+=$2 } END {print sum}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_power_nap_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_power_nap_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_power_nap_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "os_power_nap_disable passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_power_nap_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_power_nap_disable passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_power_nap_disable failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_power_nap_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "os_power_nap_disable failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_power_nap_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_power_nap_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_power_nap_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_root_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_root_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_root_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_root_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_root_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_root_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_root_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_root_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_root_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_root_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_root_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_root_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_root_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_root_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_root_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_advertising_privacy_protection_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"WebKitPreferences.privateClickMeasurementEnabled" = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_advertising_privacy_protection_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_advertising_privacy_protection_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_advertising_privacy_protection_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_advertising_privacy_protection_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_advertising_privacy_protection_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_advertising_privacy_protection_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_advertising_privacy_protection_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_advertising_privacy_protection_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_advertising_privacy_protection_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_advertising_privacy_protection_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_advertising_privacy_protection_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_advertising_privacy_protection_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_advertising_privacy_protection_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_advertising_privacy_protection_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_open_safe_downloads_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'AutoOpenSafeDownloads = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_open_safe_downloads_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_open_safe_downloads_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_open_safe_downloads_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_open_safe_downloads_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_open_safe_downloads_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_open_safe_downloads_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_open_safe_downloads_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_open_safe_downloads_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_open_safe_downloads_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_open_safe_downloads_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_open_safe_downloads_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_open_safe_downloads_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_open_safe_downloads_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_open_safe_downloads_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_popups_disabled -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'safariAllowPopups = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_popups_disabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_popups_disabled'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_popups_disabled" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_popups_disabled passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_popups_disabled" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_popups_disabled passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_popups_disabled failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_popups_disabled" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_popups_disabled failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_popups_disabled failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_popups_disabled" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_popups_disabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_popups_disabled does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_popups_disabled -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_prevent_cross-site_tracking_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -cE '"WebKitPreferences.storageBlockingPolicy" = 1|"WebKitStorageBlockingPolicy" = 1|"BlockStoragePolicy" =2' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_prevent_cross-site_tracking_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_prevent_cross-site_tracking_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_prevent_cross-site_tracking_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_prevent_cross-site_tracking_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_prevent_cross-site_tracking_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_prevent_cross-site_tracking_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_prevent_cross-site_tracking_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_prevent_cross-site_tracking_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_prevent_cross-site_tracking_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_prevent_cross-site_tracking_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_prevent_cross-site_tracking_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_prevent_cross-site_tracking_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_prevent_cross-site_tracking_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_prevent_cross-site_tracking_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_show_full_website_address_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'ShowFullURLInSmartSearchField = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_show_full_website_address_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_show_full_website_address_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_show_full_website_address_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_show_full_website_address_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_show_full_website_address_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_show_full_website_address_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_show_full_website_address_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_show_full_website_address_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_show_full_website_address_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_show_full_website_address_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_show_full_website_address_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_show_full_website_address_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_show_full_website_address_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_show_full_website_address_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_show_status_bar_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'ShowOverlayStatusBar = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_show_status_bar_enabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_show_status_bar_enabled'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_show_status_bar_enabled" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_show_status_bar_enabled passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_show_status_bar_enabled" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_show_status_bar_enabled passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_show_status_bar_enabled failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_show_status_bar_enabled" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_show_status_bar_enabled failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_show_status_bar_enabled failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_show_status_bar_enabled" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_show_status_bar_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_show_status_bar_enabled does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_show_status_bar_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: os_safari_warn_fraudulent_website_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'WarnAboutFraudulentWebsites = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_warn_fraudulent_website_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_safari_warn_fraudulent_website_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_safari_warn_fraudulent_website_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_safari_warn_fraudulent_website_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_safari_warn_fraudulent_website_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_safari_warn_fraudulent_website_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_safari_warn_fraudulent_website_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_warn_fraudulent_website_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_warn_fraudulent_website_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_safari_warn_fraudulent_website_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_safari_warn_fraudulent_website_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_safari_warn_fraudulent_website_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_safari_warn_fraudulent_website_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_safari_warn_fraudulent_website_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_show_filename_extensions_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults read .GlobalPreferences AppleShowAllExtensions 2>/dev/null
)
    # expected result {'boolean': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_show_filename_extensions_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_show_filename_extensions_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_show_filename_extensions_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_show_filename_extensions_enable passed (Result: $result_value, Expected: \"{'boolean': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_show_filename_extensions_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_show_filename_extensions_enable passed (Result: $result_value, Expected: "{'boolean': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_show_filename_extensions_enable failed (Result: $result_value, Expected: \"{'boolean': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_show_filename_extensions_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_show_filename_extensions_enable failed (Result: $result_value, Expected: "{'boolean': 1}")"
        else
            logmessage "os_show_filename_extensions_enable failed (Result: $result_value, Expected: \"{'boolean': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_show_filename_extensions_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_show_filename_extensions_enable failed (Result: $result_value, Expected: "{'boolean': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_show_filename_extensions_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_show_filename_extensions_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * AU-9, AU-9(3)
# * CM-5, CM-5(6)
# * SC-4
# * SI-2
# * SI-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sip_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sip_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_sip_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_sip_enable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_sip_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_sip_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_sip_enable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_sip_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_sip_enable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_sip_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_sip_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_sip_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_sip_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_software_update_deferral -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('enforcedSoftwareUpdateDelay')) || 0
  if ( timeout <= 30 ) {
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
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_software_update_deferral'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_software_update_deferral'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_software_update_deferral" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "os_software_update_deferral passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add finding -bool NO
        if [[ ! "$customref" == "os_software_update_deferral" ]]; then
            /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_software_update_deferral passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_software_update_deferral failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add finding -bool YES
            if [[ ! "$customref" == "os_software_update_deferral" ]]; then
                /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_software_update_deferral failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "os_software_update_deferral failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add finding -bool YES
            if [[ ! "$customref" == "os_software_update_deferral" ]]; then
              /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_software_update_deferral failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_software_update_deferral does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_software_update_deferral -dict-add finding -bool NO
fi
    
#####----- Rule: os_sudo_timeout_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudo_timeout_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudo_timeout_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_sudo_timeout_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_sudo_timeout_configure passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_sudo_timeout_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_sudo_timeout_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_sudo_timeout_configure failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_sudo_timeout_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_sudo_timeout_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_sudo_timeout_configure failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_sudo_timeout_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_sudo_timeout_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_sudo_timeout_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_sudo_timeout_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_sudoers_timestamp_type_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5(1)
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F": " '/Type of authentication timestamp record/{print $2}'
)
    # expected result {'string': 'tty'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudoers_timestamp_type_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudoers_timestamp_type_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_sudoers_timestamp_type_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "tty" ]]; then
        logmessage "os_sudoers_timestamp_type_configure passed (Result: $result_value, Expected: \"{'string': 'tty'}\")"
        /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_sudoers_timestamp_type_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_sudoers_timestamp_type_configure passed (Result: $result_value, Expected: "{'string': 'tty'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_sudoers_timestamp_type_configure failed (Result: $result_value, Expected: \"{'string': 'tty'}\")"
            /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_sudoers_timestamp_type_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_sudoers_timestamp_type_configure failed (Result: $result_value, Expected: "{'string': 'tty'}")"
        else
            logmessage "os_sudoers_timestamp_type_configure failed (Result: $result_value, Expected: \"{'string': 'tty'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_sudoers_timestamp_type_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_sudoers_timestamp_type_configure failed (Result: $result_value, Expected: "{'string': 'tty'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_sudoers_timestamp_type_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_sudoers_timestamp_type_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_system_wide_applications_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/find /Applications -iname "*\.app" -type d -perm -2 -ls | /usr/bin/wc -l | /usr/bin/xargs
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_system_wide_applications_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_system_wide_applications_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_system_wide_applications_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "os_system_wide_applications_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_system_wide_applications_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_system_wide_applications_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_system_wide_applications_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_system_wide_applications_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_system_wide_applications_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "os_system_wide_applications_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_system_wide_applications_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_system_wide_applications_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_system_wide_applications_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_system_wide_applications_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_terminal_secure_keyboard_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Terminal')\
.objectForKey('SecureKeyboardEntry').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_terminal_secure_keyboard_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_terminal_secure_keyboard_enable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_terminal_secure_keyboard_enable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "true" ]]; then
        logmessage "os_terminal_secure_keyboard_enable passed (Result: $result_value, Expected: \"{'string': 'true'}\")"
        /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_terminal_secure_keyboard_enable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_terminal_secure_keyboard_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_terminal_secure_keyboard_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\")"
            /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_terminal_secure_keyboard_enable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_terminal_secure_keyboard_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            logmessage "os_terminal_secure_keyboard_enable failed (Result: $result_value, Expected: \"{'string': 'true'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_terminal_secure_keyboard_enable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_terminal_secure_keyboard_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_terminal_secure_keyboard_enable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_terminal_secure_keyboard_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_time_offset_limit_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/sntp $(/usr/sbin/systemsetup -getnetworktimeserver | /usr/bin/awk '{print $4}') | /usr/bin/awk -F'.' '/\+\/\-/{if (substr($1,2) >= 270) {print "No"} else {print "Yes"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_time_offset_limit_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_time_offset_limit_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_time_offset_limit_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "Yes" ]]; then
        logmessage "os_time_offset_limit_configure passed (Result: $result_value, Expected: \"{'string': 'yes'}\")"
        /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_time_offset_limit_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_time_offset_limit_configure passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_time_offset_limit_configure failed (Result: $result_value, Expected: \"{'string': 'yes'}\")"
            /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_time_offset_limit_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_time_offset_limit_configure failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            logmessage "os_time_offset_limit_configure failed (Result: $result_value, Expected: \"{'string': 'yes'}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_time_offset_limit_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_time_offset_limit_configure failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_time_offset_limit_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_time_offset_limit_configure -dict-add finding -bool NO
fi
    
#####----- Rule: os_unlock_active_user_session_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c '<string>use-login-window-ui</string>'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_unlock_active_user_session_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_unlock_active_user_session_disable'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_unlock_active_user_session_disable" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "1" ]]; then
        logmessage "os_unlock_active_user_session_disable passed (Result: $result_value, Expected: \"{'integer': 1}\")"
        /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool NO
        if [[ ! "$customref" == "os_unlock_active_user_session_disable" ]]; then
            /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_unlock_active_user_session_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_unlock_active_user_session_disable failed (Result: $result_value, Expected: \"{'integer': 1}\")"
            /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_unlock_active_user_session_disable" ]]; then
                /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_unlock_active_user_session_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            logmessage "os_unlock_active_user_session_disable failed (Result: $result_value, Expected: \"{'integer': 1}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool YES
            if [[ ! "$customref" == "os_unlock_active_user_session_disable" ]]; then
              /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_unlock_active_user_session_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_unlock_active_user_session_disable does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_unlock_active_user_session_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_world_writable_system_folder_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    unset result_value
    result_value=$(/usr/bin/find /System/Volumes/Data/System -type d -perm -2 -ls | /usr/bin/grep -vE "downloadDir|locks" | /usr/bin/wc -l | /usr/bin/xargs
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_world_writable_system_folder_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_world_writable_system_folder_configure'))["exempt_reason"]
EOS
)   
    customref="$(echo "os_world_writable_system_folder_configure" | rev | cut -d ' ' -f 2- | rev)"
    customref="$(echo "$customref" | tr " " ",")"
    if [[ $result_value == "0" ]]; then
        logmessage "os_world_writable_system_folder_configure passed (Result: $result_value, Expected: \"{'integer': 0}\")"
        /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add finding -bool NO
        if [[ ! "$customref" == "os_world_writable_system_folder_configure" ]]; then
            /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add reference -string "$customref"
        fi
        /usr/bin/logger "mSCP: macosrules - os_world_writable_system_folder_configure passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            logmessage "os_world_writable_system_folder_configure failed (Result: $result_value, Expected: \"{'integer': 0}\")"
            /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_world_writable_system_folder_configure" ]]; then
                /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_world_writable_system_folder_configure failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            logmessage "os_world_writable_system_folder_configure failed (Result: $result_value, Expected: \"{'integer': 0}\") - Exemption Allowed (Reason: \"$exempt_reason\")"
            /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add finding -bool YES
            if [[ ! "$customref" == "os_world_writable_system_folder_configure" ]]; then
              /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add reference -string "$customref"
            fi
            /usr/bin/logger "mSCP: macosrules - os_world_writable_system_folder_configure failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    logmessage "os_world_writable_system_folder_configure does not apply to this architecture"
    /usr/bin/defaults write "$audit_plist" os_world_writable_system_folder_configure -dict-add finding -bool NO
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


    
#####----- Rule: os_authenticated_root_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * CM-5
# * MA-4(1)
# * SC-34
# * SI-7, SI-7(6)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_authenticated_root_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_authenticated_root_enable'))["exempt_reason"]
EOS
)

os_authenticated_root_enable_audit_score=$($plb -c "print os_authenticated_root_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_authenticated_root_enable_audit_score == "true" ]]; then
        ask 'os_authenticated_root_enable - Run the command(s)-> /usr/bin/csrutil authenticated-root enable ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_authenticated_root_enable ..."
            /usr/bin/csrutil authenticated-root enable
        fi
    else
        logmessage "Settings for: os_authenticated_root_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_authenticated_root_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_gatekeeper_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_gatekeeper_enable'))["exempt_reason"]
EOS
)

os_gatekeeper_enable_audit_score=$($plb -c "print os_gatekeeper_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_gatekeeper_enable_audit_score == "true" ]]; then
        ask 'os_gatekeeper_enable - Run the command(s)-> /usr/sbin/spctl --global-enable ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_gatekeeper_enable ..."
            /usr/sbin/spctl --global-enable
        fi
    else
        logmessage "Settings for: os_gatekeeper_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_gatekeeper_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_guest_folder_removed -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_guest_folder_removed'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_guest_folder_removed'))["exempt_reason"]
EOS
)

os_guest_folder_removed_audit_score=$($plb -c "print os_guest_folder_removed:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_guest_folder_removed_audit_score == "true" ]]; then
        ask 'os_guest_folder_removed - Run the command(s)-> /bin/rm -Rf /Users/Guest ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_guest_folder_removed ..."
            /bin/rm -Rf /Users/Guest
        fi
    else
        logmessage "Settings for: os_guest_folder_removed already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_guest_folder_removed has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_home_folders_secure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-6

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_home_folders_secure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_home_folders_secure'))["exempt_reason"]
EOS
)

os_home_folders_secure_audit_score=$($plb -c "print os_home_folders_secure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_home_folders_secure_audit_score == "true" ]]; then
        ask 'os_home_folders_secure - Run the command(s)-> IFS=$'"'"'\n'"'"'
for userDirs in $( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" ); do
  /bin/chmod og-rwx "$userDirs"
done
unset IFS ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_home_folders_secure ..."
            IFS=$'\n'
for userDirs in $( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" ); do
  /bin/chmod og-rwx "$userDirs"
done
unset IFS
        fi
    else
        logmessage "Settings for: os_home_folders_secure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_home_folders_secure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_httpd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_httpd_disable'))["exempt_reason"]
EOS
)

os_httpd_disable_audit_score=$($plb -c "print os_httpd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_httpd_disable_audit_score == "true" ]]; then
        ask 'os_httpd_disable - Run the command(s)-> /bin/launchctl disable system/org.apache.httpd ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_httpd_disable ..."
            /bin/launchctl disable system/org.apache.httpd
        fi
    else
        logmessage "Settings for: os_httpd_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_httpd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_install_log_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_install_log_retention_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_install_log_retention_configure'))["exempt_reason"]
EOS
)

os_install_log_retention_configure_audit_score=$($plb -c "print os_install_log_retention_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_install_log_retention_configure_audit_score == "true" ]]; then
        ask 'os_install_log_retention_configure - Run the command(s)-> /usr/bin/sed -i '"'"''"'"' "s/\* file \/var\/log\/install.log.*/\* file \/var\/log\/install.log format='"'"'\$\(\(Time\)\(JZ\)\) \$Host \$\(Sender\)\[\$\(PID\\)\]: \$Message'"'"' rotate=utc compress file_max=50M size_only ttl=365/g" /etc/asl/com.apple.install ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_install_log_retention_configure ..."
            /usr/bin/sed -i '' "s/\* file \/var\/log\/install.log.*/\* file \/var\/log\/install.log format='\$\(\(Time\)\(JZ\)\) \$Host \$\(Sender\)\[\$\(PID\\)\]: \$Message' rotate=utc compress file_max=50M size_only ttl=365/g" /etc/asl/com.apple.install
        fi
    else
        logmessage "Settings for: os_install_log_retention_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_install_log_retention_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_mobile_file_integrity_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_mobile_file_integrity_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_mobile_file_integrity_enable'))["exempt_reason"]
EOS
)

os_mobile_file_integrity_enable_audit_score=$($plb -c "print os_mobile_file_integrity_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_mobile_file_integrity_enable_audit_score == "true" ]]; then
        ask 'os_mobile_file_integrity_enable - Run the command(s)-> /usr/sbin/nvram boot-args="" ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_mobile_file_integrity_enable ..."
            /usr/sbin/nvram boot-args=""
        fi
    else
        logmessage "Settings for: os_mobile_file_integrity_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_mobile_file_integrity_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_nfsd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_nfsd_disable'))["exempt_reason"]
EOS
)

os_nfsd_disable_audit_score=$($plb -c "print os_nfsd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_nfsd_disable_audit_score == "true" ]]; then
        ask 'os_nfsd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.nfsd ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_nfsd_disable ..."
            /bin/launchctl disable system/com.apple.nfsd
        fi
    else
        logmessage "Settings for: os_nfsd_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_nfsd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_password_hint_remove -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-6

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_password_hint_remove'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_password_hint_remove'))["exempt_reason"]
EOS
)

os_password_hint_remove_audit_score=$($plb -c "print os_password_hint_remove:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_password_hint_remove_audit_score == "true" ]]; then
        ask 'os_password_hint_remove - Run the command(s)-> for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '"'"'$2 > 500 {print $1}'"'"'); do
  /usr/bin/dscl . -delete /Users/$u hint
done ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_password_hint_remove ..."
            for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
  /usr/bin/dscl . -delete /Users/$u hint
done
        fi
    else
        logmessage "Settings for: os_password_hint_remove already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_password_hint_remove has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_power_nap_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_power_nap_disable'))["exempt_reason"]
EOS
)

os_power_nap_disable_audit_score=$($plb -c "print os_power_nap_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_power_nap_disable_audit_score == "true" ]]; then
        ask 'os_power_nap_disable - Run the command(s)-> /usr/bin/pmset -a powernap 0 ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_power_nap_disable ..."
            /usr/bin/pmset -a powernap 0
        fi
    else
        logmessage "Settings for: os_power_nap_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_power_nap_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_root_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_root_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_root_disable'))["exempt_reason"]
EOS
)

os_root_disable_audit_score=$($plb -c "print os_root_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_root_disable_audit_score == "true" ]]; then
        ask 'os_root_disable - Run the command(s)-> /usr/bin/dscl . -create /Users/root UserShell /usr/bin/false ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_root_disable ..."
            /usr/bin/dscl . -create /Users/root UserShell /usr/bin/false
        fi
    else
        logmessage "Settings for: os_root_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_root_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_show_filename_extensions_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_show_filename_extensions_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_show_filename_extensions_enable'))["exempt_reason"]
EOS
)

os_show_filename_extensions_enable_audit_score=$($plb -c "print os_show_filename_extensions_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_show_filename_extensions_enable_audit_score == "true" ]]; then
        ask 'os_show_filename_extensions_enable - Run the command(s)-> /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write /Users/"$CURRENT_USER"/Library/Preferences/.GlobalPreferences AppleShowAllExtensions -bool true ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_show_filename_extensions_enable ..."
            /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write /Users/"$CURRENT_USER"/Library/Preferences/.GlobalPreferences AppleShowAllExtensions -bool true
        fi
    else
        logmessage "Settings for: os_show_filename_extensions_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_show_filename_extensions_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_sip_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-3
# * AU-9, AU-9(3)
# * CM-5, CM-5(6)
# * SC-4
# * SI-2
# * SI-7

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sip_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sip_enable'))["exempt_reason"]
EOS
)

os_sip_enable_audit_score=$($plb -c "print os_sip_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sip_enable_audit_score == "true" ]]; then
        ask 'os_sip_enable - Run the command(s)-> /usr/bin/csrutil enable ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_sip_enable ..."
            /usr/bin/csrutil enable
        fi
    else
        logmessage "Settings for: os_sip_enable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_sip_enable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_sudo_timeout_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudo_timeout_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudo_timeout_configure'))["exempt_reason"]
EOS
)

os_sudo_timeout_configure_audit_score=$($plb -c "print os_sudo_timeout_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sudo_timeout_configure_audit_score == "true" ]]; then
        ask 'os_sudo_timeout_configure - Run the command(s)-> /usr/bin/find /etc/sudoers* -type f -exec sed -i '"'"''"'"' '"'"'/timestamp_timeout/d'"'"' '"'"'{}'"'"' \;
/bin/echo "Defaults timestamp_timeout=0" >> /etc/sudoers.d/mscp ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_sudo_timeout_configure ..."
            /usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_timeout/d' '{}' \;
/bin/echo "Defaults timestamp_timeout=0" >> /etc/sudoers.d/mscp
        fi
    else
        logmessage "Settings for: os_sudo_timeout_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_sudo_timeout_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_sudoers_timestamp_type_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5(1)
# * IA-11

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudoers_timestamp_type_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_sudoers_timestamp_type_configure'))["exempt_reason"]
EOS
)

os_sudoers_timestamp_type_configure_audit_score=$($plb -c "print os_sudoers_timestamp_type_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_sudoers_timestamp_type_configure_audit_score == "true" ]]; then
        ask 'os_sudoers_timestamp_type_configure - Run the command(s)-> /usr/bin/find /etc/sudoers* -type f -exec sed -i '"'"''"'"' '"'"'/timestamp_type/d; /!tty_tickets/d'"'"' '"'"'{}'"'"' \; ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_sudoers_timestamp_type_configure ..."
            /usr/bin/find /etc/sudoers* -type f -exec sed -i '' '/timestamp_type/d; /!tty_tickets/d' '{}' \;
        fi
    else
        logmessage "Settings for: os_sudoers_timestamp_type_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_sudoers_timestamp_type_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_system_wide_applications_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_system_wide_applications_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_system_wide_applications_configure'))["exempt_reason"]
EOS
)

os_system_wide_applications_configure_audit_score=$($plb -c "print os_system_wide_applications_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_system_wide_applications_configure_audit_score == "true" ]]; then
        ask 'os_system_wide_applications_configure - Run the command(s)-> IFS=$'"'"'\n'"'"'
for apps in $( /usr/bin/find /Applications -iname "*\.app" -type d -perm -2 ); do
  /bin/chmod -R o-w "$apps"
done ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_system_wide_applications_configure ..."
            IFS=$'\n'
for apps in $( /usr/bin/find /Applications -iname "*\.app" -type d -perm -2 ); do
  /bin/chmod -R o-w "$apps"
done
        fi
    else
        logmessage "Settings for: os_system_wide_applications_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_system_wide_applications_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_time_offset_limit_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_time_offset_limit_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_time_offset_limit_configure'))["exempt_reason"]
EOS
)

os_time_offset_limit_configure_audit_score=$($plb -c "print os_time_offset_limit_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_time_offset_limit_configure_audit_score == "true" ]]; then
        ask 'os_time_offset_limit_configure - Run the command(s)-> /usr/bin/sntp -Ss $(/usr/sbin/systemsetup -getnetworktimeserver | /usr/bin/awk '"'"'{print $4}'"'"') ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_time_offset_limit_configure ..."
            /usr/bin/sntp -Ss $(/usr/sbin/systemsetup -getnetworktimeserver | /usr/bin/awk '{print $4}')
        fi
    else
        logmessage "Settings for: os_time_offset_limit_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_time_offset_limit_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_unlock_active_user_session_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-2, IA-2(5)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_unlock_active_user_session_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_unlock_active_user_session_disable'))["exempt_reason"]
EOS
)

os_unlock_active_user_session_disable_audit_score=$($plb -c "print os_unlock_active_user_session_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_unlock_active_user_session_disable_audit_score == "true" ]]; then
        ask 'os_unlock_active_user_session_disable - Run the command(s)-> /usr/bin/security authorizationdb write system.login.screensaver "use-login-window-ui" ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_unlock_active_user_session_disable ..."
            /usr/bin/security authorizationdb write system.login.screensaver "use-login-window-ui"
        fi
    else
        logmessage "Settings for: os_unlock_active_user_session_disable already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_unlock_active_user_session_disable has an exemption, remediation skipped (Reason: "$exempt_reason")"
fi
    
#####----- Rule: os_world_writable_system_folder_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_world_writable_system_folder_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.macosrules.audit').objectForKey('os_world_writable_system_folder_configure'))["exempt_reason"]
EOS
)

os_world_writable_system_folder_configure_audit_score=$($plb -c "print os_world_writable_system_folder_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_world_writable_system_folder_configure_audit_score == "true" ]]; then
        ask 'os_world_writable_system_folder_configure - Run the command(s)-> IFS=$'"'"'\n'"'"'
for sysPermissions in $( /usr/bin/find /System/Volumes/Data/System -type d -perm -2 | /usr/bin/grep -vE "downloadDir|locks" ); do
  /bin/chmod -R o-w "$sysPermissions"
done ' N
        if [[ $? == 0 ]]; then
            logmessage "Running the command to configure the settings for: os_world_writable_system_folder_configure ..."
            IFS=$'\n'
for sysPermissions in $( /usr/bin/find /System/Volumes/Data/System -type d -perm -2 | /usr/bin/grep -vE "downloadDir|locks" ); do
  /bin/chmod -R o-w "$sysPermissions"
done
        fi
    else
        logmessage "Settings for: os_world_writable_system_folder_configure already configured, continuing..."
    fi
elif [[ ! -z "$exempt_reason" ]];then
    logmessage "os_world_writable_system_folder_configure has an exemption, remediation skipped (Reason: "$exempt_reason")"
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
    