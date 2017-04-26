
# *=============================================================
#
# CSI-HD-Securing Script
#
# Copyright (c) German Cancer Research Center,
# Division of Medical and Biological Informatics.
# Division of Radiology
# All rights reserved.
#
# This software is distributed WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.
#
# Author: Ignaz Reicht
# =============================================================*

#!/bin/bash


##
# run this script using sudo
##

###   T A B L E  of  C O N T E N T    ###
###===================================###
#
# ----- Error Codes
# ---- Global Variables
# --- Generic Functions
# -- Specialized Functions
# - Main Program


###=============================###
###   E R R O R    C O D E S    ###
###=============================###
# 3: YES
CODE_YES=3
# 4: NO
CODE_NO=4
# 33:

#Get error codes not confused with return values:
# $? == 0 means all ok
# $? != 0 means something went wrong


###=======================================###
###   G L O B A L    V A R I A B L E S    ###
###   A N D  C O N F I G U R A T I O N    ###
###=======================================###

source ./CSI-HD.conf

LogDay=$(date '+%Y-%m-%d')
LogFile=secUbuntu_$LogDay.log

if [ $SUDO_USER ]; then UserName=$SUDO_USER; else UserName=`whoami`; fi

OVERALLERROR=0
OVERALLSUCCESS=0
VERBOSITY=0
YES="YES"


###=======================================###
###   G E N E R I C   F U N C T I O N S   ###
###=======================================###
## include some useful functions from helper script
source ./CSI-HD-helper.sh


###===============================================###
###   S P E C I A L I C E D   F U N C T I O N S   ###
###===============================================###

# Dialogue to set new Portnumber for incoming SSH connection
doAskForSSHPort()
{
  local isDoneSSHPort="FALSE"

  while [[ $isDoneSSHPort == "FALSE" ]] ; do
    # make sure input is number
    if [[ "$NEWSSHPORT" =~ ^[0-9]+$ ]] ; then
      doConfirmSSHPort=$( userConfirm "Confirm new SSH Port $NEWSSHPORT ?" )
    else
      echo "Please provide numeric input for SSH port"
    fi

    # if user agrees to new portnumber, store it, otherwise ask for differnet portnumber
    if [[ $doConfirmSSHPort == "YES" ]] ; then
      isDoneSSHPort="TRUE"
      echo "SSH configured for Port: $NEWSSHPORT"

    else
      read -r -p "please provide new SSH port: " $NEWSSHPORT

    fi
  done
}

## Check for firewall installation and configuration
# keep this function for sanity check later
isUFWActive()
{
  #do not add any additional echo commands within the methods, 
  #otherwise the greps might fail
  local statusUFWraw=$(  sudo ufw status | grep Status );
  local statusUFW=${statusUFWraw#*:}

  if   [[ `echo $statusUFW | tr [:upper:] [:lower:]` == `echo "InAcTiVe" | tr [:upper:] [:lower:]` ]] ; then
    echo "FALSE"

  elif [[ `echo $statusUFW | tr [:upper:] [:lower:]` == `echo "aCtIvE" | tr [:upper:] [:lower:]` ]] ; then
    echo "TRUE"

  else
    echo "ERROR"
  fi

}


## Configure firewall UFW
doConfigureUFW()
{
  # UFW automatically configures rules for: (ToDo add to testing, sanity check)
  #  * system internal loopback communication (ACCEPT all -- lo any anywhere anywhere; ACCEPT all -- any lo anywhere anywhere )
  #  * blocking of INVALID packages (DROP all -- any any anywhere anywhere ctstate INVALID; LOG all -- any any anywhere anywhere ctstate INVALID )
  #  
  # Added additional ip(6)tables rules for routers and neighbourhood discovery to reduce 
  # unnecessary log entries which can cause false positive PSAD alert messages
  
  #// do not separate //
  sudo ufw disable
  if [[ $? != "0" ]] ; then return 20 ; fi
  #// -------------- //
  sudo ufw --force reset >/dev/null
  if [[ $? != "0" ]] ; then return 21 ; fi
  #// -------------- //
  sudo ufw logging on >/dev/null
  if [[ $? != "0" ]] ; then return 22 ; fi
  #// -------------- //
  sudo ufw default deny >/dev/null
  if [[ $? != "0" ]] ; then return 23 ; fi
  #// -------------- //
  sudo ufw allow $NEWSSHPORT/tcp >/dev/null
  if [[ $? != "0" ]] ; then return 24 ; fi
  #// -------------- //
  sudo ufw limit $NEWSSHPORT/tcp >/dev/null
  if [[ $? != "0" ]] ; then return 25 ; fi
  #// -------------- //


  # Enable additional Logging

  newParameterUfw=()
  newParameterUfw+=('-A FORWARD -j LOG')
  newParameterUfw+=('-A INPUT -j LOG')
  newParameterUfw+=('# custom psad logging directives')

  # Avoid logging of igmp messages from local router or neighbourhood devices
  # Avoid logging of system multicast messages

  newParameterUfwIpv4=()
  newParameterUfwIpv4+=('-A ufw-before-input -p igmp -m ttl --ttl-eq 1 -j ACCEPT')
  newParameterUfwIpv4+=('-A ufw-before-input -p udp -m ttl --ttl-eq 1 -d 224.0.0.1 -j ACCEPT')
  newParameterUfwIpv4+=('# avoid logging of system multicast messages and neighbourhood discovery')

  #// -------------- //
  doAppendLinesToExactParameterInFile "COMMIT" newParameterUfwIpv4[@] "/etc/ufw/before.rules" "-stack"
  if [[ $? != "0" ]] ; then return 26 ; fi
  #// -------------- //
  doAppendLinesToExactParameterInFile "COMMIT" newParameterUfw[@] "/etc/ufw/before.rules" "-stack"
  if [[ $? != "0" ]] ; then return 26 ; fi
  #// -------------- //
  doAppendLinesToExactParameterInFile "COMMIT" newParameterUfw[@] "/etc/ufw/before6.rules" "-stack"
  if [[ $? != "0" ]] ; then return 26 ; fi
  #// -------------- //  


  # IPv6 drop  
  if [[ $DROP_IPV6_TRAFFIC == "YES" ]] ; then    
 	# #// -------------- //
 	sudo ip6tables -I INPUT -j DROP
 	if [[ $? != "0" ]] ; then return 27 ; fi
   	#// -------------- //
 	sudo ip6tables -I OUTPUT -j DROP
 	if [[ $? != "0" ]] ; then return 27 ; fi
   	#// -------------- //
 	sudo ip6tables -I FORWARD -j DROP
 	if [[ $? != "0" ]] ; then return 27 ; fi
   	#// -------------- //
  
  else	
  	newParameterUfw=()
    newParameterUfw+=('-I ufw6-before-input 34 -p udp -d ff02::1 --match hl --hl-eq 1 -j ACCEPT')
    newParameterUfw+=('# avoid ip6-allnodes logging')
 	#// -------------- //
    doAppendLinesToExactParameterInFile "COMMIT" newParameterUfw[@] "/etc/ufw/before6.rules" "-stack"
    if [[ $? != "0" ]] ; then return 28 ; fi
    #// -------------- //  
  fi
  
  sudo ufw enable >/dev/null
  if [[ $? != "0" ]] ; then return 29 ; fi
  #// -------------- //
  
  return 0

#echo $(date '+%Y-%m-%d %H:%M:%S') > ufwRuleStatus_current.txt
#  sudo ufw status verbose > ufwRuleStatus_current.txt

}


## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ##
## ================================================ ##
## =================== M A I N ==================== ##
## =================~~~~~~~~~~~~~================== ##
## ================ P R O G R A M ================= ##
## ================================================ ##
## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ##




## Handling of optional script flags
##================================##

while getopts "v" opt; do
  case $opt in
  v)
    VERBOSITY=1
    echo "[ENABLED] Verbosity"
    ;;
  esac
done

##================================##


#####
##DEBUG
#if [[ "skip" == "THIS" ]] ; then
######


echo -n "Checking install status of package postfix ..."
isPostfixInstalled=$( isPackageInstalled "postfix" )
if [[ $isPostfixInstalled == $YES ]] ; then
  echo_success
else

  # some packages require postfix for notifications, therefore pre-setup postfix without userinteraction during package installation
  sudo debconf-set-selections <<< "postfix postfix/mailname string $MAILDOMAIN"
  sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string Internet Site"
  #// do not separate //
  doInstall "postfix "
  doPrintStatus "$?"
  #// -------------- //

fi


## ====================
## ===== SSH Port =====
# suggest to switch SSH port to non-default number.

echo -n "Checking SSH Port ..."

#// do not separate //
doAskForSSHPort
doPrintStatus "$?"
#// -------------- //


## ========================
## ===== FIREWALL UFW =====
# 1. Check if UFW is installed
# 2. (Re-)configure UFW; Logging for PSAD is enabled

echo -n "Checking status of firewall ufw ..."
isUFWinstalled=$( isPackageInstalled "ufw" )
if [[ $isUFWinstalled == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "ufw "
  doPrintStatus "$?"
  #// -------------- //
fi

echo -n "Configure UFW ..."
#// do not separate //
doConfigureUFW
doPrintStatus "$?"
#// -------------- //



#### DEBUG
#if [[ "skip" == "THIS" ]] ; then
######



## ================================
## ===== Secure shared memory =====

echo -n "Secure shared memory ..."

hasTmpfs=$( grep -c "tmpfs" /etc/fstab )
if [[ $hasTmpfs != "0" ]] ; then
#  echo "/etc/fstab already contains tmpfs"
  echo_success

else
  ## create read-only backupfile
  echo -n "Backing up current fstab ..."

  timestamp=$(date '+%Y-%m-%d-%H%M%S')
  sudo cp /etc/fstab /etc/fstab.backup.$timestamp

  #// do not separate //
  sudo chmod a-w /etc/fstab.backup.$timestamp
  doPrintStatus "$?"
  #// -------------- //

  ## create read-only backupfile
  echo -n "Adding entries to fstab ..."
  printf '%s\n' "$LogDay, $timestamp - Script Entry - Secure Shared Memory" >> /etc/fstab
  #// do not separate //
  printf '%s\n' "tmpfs\t/run/shm\ttmpfs\tdefaults,noexec,nosuid\t0\t0" >> /etc/fstab
  doPrintStatus "$?"
  #// -------------- //

fi


## =========================
## ===== SSH Hardening =====

echo "=== SSH Hardening ==="

#check if ssh server is installed, if not, install
openSSHSName="openssh-server"
isOpenSSHSinstalled=$(isPackageInstalled $openSSHSName)

if [[ $isOpenSSHSinstalled == "NO" ]] ; then
  echo -n "installing openssh-server"

  #// do not separate //
  doInstall $openSSHSName
  doPrintStatus "$?"
  #// -------------- //
fi

## create read-only backupfile
timestamp=$(date '+%Y-%m-%d-%H%M%S')
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.factory-defaults.$timestamp
sudo chmod a-w /etc/ssh/sshd_config.factory-defaults.$timestamp

echo -n "Setting new SSH Port; $NEWSSHPORT ..."

#// do not separate //
doUpdateParameterInFile "Port" "Port $NEWSSHPORT" "/etc/ssh/sshd_config"
doPrintStatus "$?"
#// -------------- //

echo -n "Setting Protocol ..."

#// do not separate //
doUpdateParameterInFile "Protocol" "Protocol 2" "/etc/ssh/sshd_config"
doPrintStatus "$?"
#// -------------- //

echo -n "Setting PermitRootLogin ..."

#// do not separate //
doUpdateParameterInFile "PermitRootLogin" "PermitRootLogin no" "/etc/ssh/sshd_config"
doPrintStatus "$?"
#// -------------- //

#// do not separate //
sudo /etc/init.d/ssh restart
doPrintStatus "$?"
#// -------------- //


## =========================
## ===== SSL hardening =====
# TODO


## ===========================
## ===== limit su admins =====

echo "=== Limit SU Admins to dedicated group ==="

addAdminUser="$UserName"
isDone="FALSE"

while [[ $isDone != "TRUE" ]] ; do

  # Check if new group already exists
  groupCheck=$(grep -c -w "$RESTRICT_SU_TO_GROUP" /etc/group)

  if [[ $groupCheck != "0" ]] ; then
    # group already exists
    echo "# Group: $RESTRICT_SU_TO_GROUP already exists. Group not added"
    read -r -p "please provide different groupname:" RESTRICT_SU_TO_GROUP

  else
    echo -n "Adding new Admin Group: $RESTRICT_SU_TO_GROUP ..."

    #// do not separate //
    sudo groupadd  $RESTRICT_SU_TO_GROUP
    doPrintStatus "$?"
    #// -------------- //

    echo -n "# User: $addAdminUser added to the Group: $RESTRICT_SU_TO_GROUP"

    #// do not separate //
    sudo usermod -a -G $RESTRICT_SU_TO_GROUP $addAdminUser
    doPrintStatus "$?"
    #// -------------- //

    echo -n "Overwriting /bin/su for access only by $RESTRICT_SU_TO_GROUP members ..."
    
    #// do not separate //
    sudo dpkg-statoverride --update --add root $RESTRICT_SU_TO_GROUP 4750 /bin/su
    doPrintStatus "$?"
    #// -------------- //
    
    isDone="TRUE"
  fi
done


## ======================================
## ===== harden network with sysctl =====

echo "=== Hardening sysctl ==="
echo -n "Backup sysctl.conf ..."

timestamp=$(date '+%Y-%m-%d-%H%M%S')
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bkup.$timestamp

#// do not separate //
sudo chmod a-w /etc/sysctl.conf.bkup.$timestamp
doPrintStatus "$?"
#// -------------- //

# Variable to provide summarized representation of updating sysctl.conf
# if updates are successful,no errorcodes are added and value remains 0.
errorSumSCTL=0

echo -n "Update file sysctl.conf ..."

#// do not separate //
doUpdateParameterInFile "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.all.rp_filter = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.default.rp_filter" "net.ipv4.conf.default.rp_filter = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.icmp_echo_ignore_broadcasts" "net.ipv4.icmp_echo_ignore_broadcasts = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.all.accept_source_route" "net.ipv4.conf.all.accept_source_route = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv6.conf.all.accept_source_route" "net.ipv6.conf.all.accept_source_route = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.default.accept_source_route" "net.ipv4.conf.default.accept_source_route = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv6.conf.default.accept_source_route" "net.ipv6.conf.default.accept_source_route = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.send_redirects = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.default.send_redirects" "net.ipv4.conf.default.send_redirects = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.tcp_syncookies" "net.ipv4.tcp_syncookies = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.tcp_max_syn_backlog" "net.ipv4.tcp_max_syn_backlog = 2048" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.tcp_synack_retries" "net.ipv4.tcp_synack_retries = 2" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.tcp_syn_retries" "net.ipv4.tcp_syn_retries = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.all.log_martians" "net.ipv4.conf.all.log_martians = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.icmp_ignore_bogus_error_responses" "net.ipv4.icmp_ignore_bogus_error_responses = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.all.accept_redirects = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv6.conf.all.accept_redirects" "net.ipv6.conf.all.accept_redirects = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.conf.default.accept_redirects" "net.ipv4.conf.default.accept_redirects = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv6.conf.default.accept_redirects" "net.ipv6.conf.default.accept_redirects = 0" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //
doUpdateParameterInFile "net.ipv4.icmp_echo_ignore_all" "net.ipv4.icmp_echo_ignore_all = 1" "/etc/sysctl.conf" "-gd"
errorSumSCTL=$((errorSumSCTL+$?))
#// -------------- //


doPrintStatus "$errorSumSCTL"


echo "reloading sysctl ..."
#// -------------- //
sudo sysctl -p >/dev/null
doPrintStatus "$?"
#// -------------- //


## ==============================================================
## ===== Disable Open DNS Recursion and Remove Version Info =====

# ToDo

## ===============================
## ===== Prevent IP Spoofing =====

echo "=== Prevent IP Spoofing ==="
echo -n "Backup configuration host.conf ..."

timestamp=$(date '+%Y-%m-%d-%H%M%S')
sudo cp /etc/host.conf /etc/host.conf.bkup.$timestamp

#// do not separate //
sudo chmod a-w /etc/host.conf.bkup.$timestamp
doPrintStatus "$?"
#// -------------- //


echo -n "Configure host.conf ..."

# Variable to provide summarized representation of updating host.conf
# if updates are successful, no errorcodes are added and value remains 0.
errorSumHOST=0

#// do not separate //
doUpdateParameterInFile "order" "order bind,hosts" "/etc/host.conf"
errorSumHOST=$((errorSumHOST+$?))
#// -------------- //

#// do not separate //
doUpdateParameterInFile "nospoof" "nospoof on" "/etc/host.conf"
errorSumHOST=$((errorSumHOST+$?))
#// -------------- //
doPrintStatus "$errorSumHOST"

## ======================
## ===== Harden PHP =====

# ToDo

## ===============================================
## ===== Restrict Apache Information Leakage =====

isApacheInstalled=$(isPackageInstalled "apache2")
if [[ $isApacheInstalled == "TRUE" ]] ; then
  # ToDo
  echo "apache is installed, so perform all apache security configurations"
fi

## =======================
## ===== Modsecurity =====

if [[ $isApacheInstalled == "TRUE" ]] ; then
  # Variable to provide summarized representation of installing multiple packages
  # if updates are successful, no errorcodes are added and value remains 0.
  errorSumINST=0

  echo -n "Installing dependencies ..."

  #// do not separate //
  doInstall "libxml2"
  errorSumINST=$((errorSumINST+$?))
  #// -------------- //
  doInstall "libxml2-dev"
  errorSumINST=$((errorSumINST+$?))
  #// -------------- //
  doInstall "libxml2-utils"
  errorSumINST=$((errorSumINST+$?))
  #// -------------- //
  doInstall "libaprutil1"
  errorSumINST=$((errorSumINST+$?))
  #// -------------- //
  doInstall "libaprutil1-dev"
  errorSumINST=$((errorSumINST+$?))
  #// -------------- //
  doPrintStatus "$errorSumINST"


  echo -n "Creating symbolic link to libxml2.so.2 [64bit] ..."
  #// do not separate //
  ln -s /usr/lib/x86_64-linux-gnu/libxml2.so.2 /usr/lib/libxml2.so.2
  doPrintStatus "$?"
  #// -------------- //

  echo -n "Installing Apache ModSecurity package ..."

  #// do not separate //
  doInstall "libapache-mod-security"
  doPrintStatus "$?"
  #// -------------- //

  echo -n "Activate Apache ModSecurity recommended rules ..."

  #// do not separate //
  sudo mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  doPrintStatus "$?"
  #// -------------- //

  echo -n "Backup configuration modsecurity.conf ..."

  timestamp=$(date '+%Y-%m-%d-%H%M%S')
  sudo cp /etc/modsecurity/modsecurity.conf /etc/modsecurity/modsecurity.conf.bkup.$timestamp
  #// do not separate //
  sudo chmod a-w /etc/modsecurity/modsecurity.conf.bkup.$timestamp
  doPrintStatus "$?"
  #// -------------- //

  echo -n "Configuring modsecurity.conf ..."

  # Variable to provide summarized representation of installing multiple packages
  # if updates are successful, no errorcodes are added and value remains 0.
  errorSumMODS=0


  #// do not separate //
  doUpdateParameterInFile "SecRequestBodyLimit" "SecRequestBodyLimit $MODSEC_LIMIT_SIZE" "/etc/modsecurity/modsecurity.conf"
  errorSumMODS=$((errorSumMODS+$?))
  #// -------------- //

  #// do not separate //
  doUpdateParameterInFile "SecRequestBodyInMemoryLimit" "SecRequestBodyInMemoryLimit $MODSEC_LIMIT_SIZE" "/etc/modsecurity/modsecurity.conf"
  errorSumMODS=$((errorSumMODS+$?))
  #// -------------- //

  #// do not separate //
  doUpdateParameterInFile "SecRuleEngine" "SecRuleEngine On" "/etc/modsecurity/modsecurity.conf"
  errorSumMODS=$((errorSumMODS+$?))
  #// -------------- //

  #// do not separate //
  doUpdateParameterInFile "SecServerSignature" "SecServerSignature FreeOSHTTP" "/etc/modsecurity/modsecurity.conf"
  errorSumMODS=$((errorSumMODS+$?))
  #// -------------- //

  doPrintStatus "$errorSumMODS"

# ToDo Download and install the latest OWASP Core Rule Set:
# https://www.thefanclub.co.za/how-to/how-install-apache2-modsecurity-and-modevasive-ubuntu-1204-lts-server
fi



## =================================================
## ===== ModEvasive (protect from DDOS attacks) =====

if [[ $isApacheInstalled == $YES ]] ; then
  echo -n "Installing ModEvasive ..."

  #// do not separate //
  doInstall "libapache2-mod-evasive"
  doPrintStatus "$?"
  #// -------------- //

  echo -n "Creating Log File for ModEvasive ..."

  #// do not separate //
  sudo mkdir /var/log/mod_evasive
  doPrintStatus "$?"
  #// -------------- //

  echo -n "Changing Logfile permission ..."

  #// do not separate //
  sudo chown www-data:www-data /var/log/mod_evasive/
  doPrintStatus "$?"
  #// -------------- //
  #ToDo configuration
fi



## ==============================================
## ===== Scan logs and ban suspicious hosts =====

echo "=== Scan logs and ban suspicious hosts ==="

isDenyhostsInstalled=$(isPackageInstalled "denyhosts")
echo -n "Install Status of package denyhosts ..."
if [[ $isDenyhostsInstalled == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall denyhosts
  doPrintStatus "$?"
  #// -------------- //

fi

echo -n "Backing up denyhosts.conf ..."

timestamp=$(date '+%Y-%m-%d-%H%M%S')
sudo cp /etc/denyhosts.conf /etc/denyhosts.conf.bkup.$timestamp

#// do not separate //
sudo chmod a-w /etc/denyhosts.conf.bkup.$timestamp
doPrintStatus "$?"
#// -------------- //

echo -n "Updating configuration denyhosts.conf ..."

# Variable to provide summarized representation of updating file denyhosts.conf
# if updates are successful, no errorcodes are added and value remains 0.
errorSumDHOSTS=0

#// do not separate //
doUpdateParameterInFile "ADMIN_EMAIL" "ADMIN_EMAIL = $NOTIFICATIONEMAIL" "/etc/denyhosts.conf"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //
doUpdateParameterInFile "SMTP_HOST" "SMTP_HOST = localhost" "/etc/denyhosts.conf"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //
doUpdateParameterInFile "SMTP_PORT" "SMTP_PORT = 25" "/etc/denyhosts.conf"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //
doUpdateParameterInFile "SMTP_FROM" "SMTP_FROM = DenyHosts <denyhostsABC@$MAILDOMAIN> " "/etc/denyhosts.conf" "-gd"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //
doCommentOutInFile "SYSLOG_REPORT" "/etc/denyhosts.conf"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //
doCommentOutInFile "SMTP_USERNAME" "/etc/denyhosts.conf"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //
doCommentOutInFile "SMTP_PASSWORD" "/etc/denyhosts.conf"
errorSumDHOSTS=$((errorSumDHOSTS+$?))
#// -------------- //

doPrintStatus "$errorSumDHOSTS"

echo "restarting denyhosts..."

#// do not separate //
sudo /etc/init.d/denyhosts restart
doPrintStatus "$?"
#// -------------- //




## =========================================
## ===== PortScanAttackDetector - PSAD =====
# info: psadwatchd and kmsgsd are not needed anymore on OS like ubuntu16

echo -n "Checking install status of PSAD Intrusion Detection ..."
isPsadInstalled=$( isPackageInstalled "psad" )

if [[ $isPsadInstalled == $YES ]] ; then
  echo_success

else
  #// do not separate //
  echo -n -e "\n ...Installing..."
  doInstall "psad"
  doPrintStatus "$?"
  #// -------------- //
fi

echo -n "Backing up current psad configuration ..."

timestamp=$(date '+%Y-%m-%d-%H%M%S')
sudo cp /etc/psad/psad.conf /etc/psad/psad.conf.bkup.$timestamp

#// do not separate //
sudo chmod a-w /etc/psad/psad.conf.bkup.$timestamp
doPrintStatus "$?"
#// -------------- //

echo -n "Updating PSAD configuration file ..."
# Variable to provide summarized representation of updating file psad.conf
# if updates are successful, no errorcodes are added and value remains 0.
errorSumPSAD=0

#// do not separate //
doUpdateParameterInFile "EMAIL_ADDRESSES" "EMAIL_ADDRESSES  $NOTIFICATIONEMAIL;" "/etc/psad/psad.conf" "-gd"
errorSumPSAD=$((errorSumPSAD+$?))
#// -------------- //
doUpdateParameterInFile "HOSTNAME" "HOSTNAME  $MYHOSTNAME;" "/etc/psad/psad.conf" "-gd"
errorSumPSAD=$((errorSumPSAD+$?))
#// -------------- //
doUpdateParameterInFile "ENABLE_AUTO_IDS " "ENABLE_AUTO_IDS Y;" "/etc/psad/psad.conf" "-gd"
errorSumPSAD=$((errorSumPSAD+$?))
#// -------------- //
doUpdateParameterInFile "ENABLE_AUTO_IDS_EMAILS" "ENABLE_AUTO_IDS_EMAILS  Y;" "/etc/psad/psad.conf" "-gd"
errorSumPSAD=$((errorSumPSAD+$?))
#// -------------- //
doUpdateParameterInFile "IPT_SYSLOG_FILE" "IPT_SYSLOG_FILE    /var/log/syslog;" "/etc/psad/psad.conf"
errorSumPSAD=$((errorSumPSAD+$?))
#// -------------- //
doUpdateParameterInFile "EMAIL_THROTTLE" "EMAIL_THROTTLE    10;" "/etc/psad/psad.conf"
errorSumPSAD=$((errorSumPSAD+$?))
#// -------------- //

doPrintStatus "$errorSumPSAD"


## use package iptables-persistent to make sure changed rulesets are still available after reboot
## if ufw is used, then this is not needed
## it is only needed when drop of ipv6 traffic is enabled.
echo -n "Checking install status of package IPTables-Persistent ..."
isPersistentInstalled=$( isPackageInstalled "iptables-persistent" )
if [[ $isPersistentInstalled == $YES ]] ; then
  echo_success

else
  # autoconfigure iptables to avoid userinteraction
  sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
  sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
  #// do not separate //
  doInstall "iptables-persistent"
  doPrintStatus "$?"
  #// -------------- //
fi
echo -n "Start service iptables-persistent ..."
sudo /etc/init.d/netfilter-persistent start
doPrintStatus "$?"

# on some systems ip6tables could not be loaded successfully during startup, therefore perform additonal start using cron.
echo -n "Set cronjob as workaround for a clean start of iptables-persistent service ..."

#check if cronjob already exists
#// do not separate //
sudo crontab -l | grep "netfilter-persistent restart" >/dev/null
if [[ $? == "0" ]] ; then
  echo_success # cronjob already exists for this task
else
  #// do not separate //
  (sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "@reboot /etc/init.d/netfilter-persistent restart") | sudo crontab -u root -
  doPrintStatus "$?"
  #// -------------- //
fi
#// -------------- //

echo "--Reloading and Restarting PSAD service"
sudo psad -R >/dev/null
doPrintStatus "$?"
echo "--signature update"
sudo psad --sig-update >/dev/null
doPrintStatus "$?"




echo -n "Setup cronjob for psad sig-update (Sundays at 8:00am 0 8 * * 7) ..."
#check if cronjob already exists
#// do not separate //
sudo crontab -l | grep "psad *--sig-update" >/dev/null
if [[ $? == 0 ]] ; then
  echo_success # cronjob already exists for this task
else
#// do not separate //
  (sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "0 8 * * 7 /usr/sbin/psad --sig-update; /usr/sbin/psad -H") | sudo crontab -u root -
  doPrintStatus "$?"
#// -------------- //
fi
#// -------------- //


##sanity check
echo -n "Check if psad service is running ..."
#// do not separate //
sudo service psad status >/dev/null
doPrintStatus "$?"
#// -------------- //

####DEBUG
#fi
#exit
########
## ========================================================
## ===== Check for rootkits - RKHunter and CHKRootKit =====
## RKHunter has cronjob in cron.daily
## CHKRootKit daily cronjob is disabled by default

echo "=== ROOTKIT MONITORING ==="

echo -n "Checking install status of package CHKROOTKIT ..."

isCHKinstalled=$( isPackageInstalled "chkrootkit" )
if [[ $isCHKinstalled == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "chkrootkit"
  doPrintStatus "$?"
  #// -------------- //

fi

echo -n "Setup Cronjob for running chkrootkit (daily at 3am) ..."


#check if cronjob already exists
#// do not separate //
sudo crontab -l | grep "chkrootkit" >/dev/null
if [[ $? == 0 ]] ; then
echo_success # cronjob already exists for this task
else
#// do not separate //
(sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "0 3 * * * /usr/sbin/chkrootkit 2>&1 | mail -s \"chkrootkit report\" -r \"CHKROOTKIT CRON\" $NOTIFICATIONEMAIL") | sudo crontab -u root -
doPrintStatus "$?"
#// -------------- //
fi
#// -------------- //


echo -n "Running chkrootkit, results sending to your email: $NOTIFICATIONEMAIL ..."
#// do not separate //
sudo chkrootkit | mail -s "Chkrootkit Initial Report" -r "CHKROOTKIT" $NOTIFICATIONEMAIL
doPrintStatus "$?"
#// -------------- //

###DEBUG
## end of skip
#fi
#############


echo -n "Checking install status of package RKHUNTER ..."

isRKHinstalled=$( isPackageInstalled "rkhunter" )
if [[ $isRKHinstalled == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "rkhunter"
  doPrintStatus "$?"
  #// -------------- //

fi

# To update and run RKHunter
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --versioncheck



# Variable to provide summarized representation of updating file rkhunter.conf
# if updates are successful, no errorcodes are added and value remains 0.
errorSumRKHUNT=0

echo -n "Updating RKHUNTER configuration file ..."

#// do not separate //
doUpdateParameterInFile "CRON_DAILY_RUN" "CRON_DAILY_RUN=\"true\" " "/etc/default/rkhunter"
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- //
doUpdateParameterInFile "CRON_DB_UPDATE" "CRON_DB_UPDATE=\"true\" " "/etc/default/rkhunter"
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- //
doUpdateParameterInFile "DB_UPDATE_EMAIL" "DB_UPDATE_EMAIL=\"true\" " "/etc/default/rkhunter"
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- //
doUpdateParameterInFile "REPORT_EMAIL" "REPORT_EMAIL=\"$NOTIFICATIONEMAIL\" " "/etc/default/rkhunter"
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- //
doUpdateParameterInFile "APT_AUTOGEN" "APT_AUTOGEN=\"true\" " "/etc/default/rkhunter"
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- // The PKGMGR option tells rkhunter to use the specified package manager to obtain the file property information.
doUpdateParameterInFile "PKGMGR" "PKGMGR=DPKG" "/etc/rkhunter.conf" "-gd"
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- //
doUpdateParameterInFile "ALLOWDEVFILE=/dev/shm/pulse-shm" "ALLOWDEVFILE=/dev/shm/pulse-shm-*" "/etc/rkhunter.conf" "-gd" #uncomment shared memory objects to be whitelisted
errorSumRKHUNT=$((errorSumRKHUNT+$?))
#// -------------- //
doPrintStatus "$errorSumRKHUNT"



echo "Running rkhunter ..."
sudo rkhunter --check --sk


echo -n "Setup Cronjob for rkhunter versionupdate (daily at 3:00am) ..."
#check if cronjob already exists
#// do not separate //
sudo crontab -l | grep "rkhunter *--versioncheck" >/dev/null
if [[ $? == 0 ]] ; then
echo_success # cronjob already exists for this task
else
#// do not separate //
(sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "0 3 * * * sudo rkhunter --versioncheck") | sudo crontab -u root -
doPrintStatus "$?"
#// -------------- //
fi
#// -------------- //



## ==================================
## ===== NMAP - Network Scanner =====

echo -n "Checking install status of package NMAP ..."

isNmapInstalled=$( isPackageInstalled "nmap" )
if [[ $isNmapInstalled == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "nmap"
  doPrintStatus "$?"
  #// -------------- //

fi

## Scan your system for open ports and OS detection
sudo nmap -v -sT -A localhost
sudo nmap -v -sT -A -6 ::1



## =================================================
## ===== LogWatch - Analysing system LOG files =====

statLogWatchinstall=$( isPackageInstalled "logwatch" )
statLibDateinstall=$( isPackageInstalled "libdate-manip-perl" )

echo -n "Checking install status of package LOGWATCH ..."
if [[ $statLogWatchinstall == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "logwatch"
  doPrintStatus "$?"
  #// -------------- //

  # Create a directory the Logwatch package in the repositories currently does not create, but is required for proper operation:
  # help.ubuntu.com/community/Logwatch
  sudo mkdir /var/cache/logwatch

  #remove default cronjobs since we modify them according to our needs, especially notificationemails
  if [[ -e /etc/cron.daily/00logwatch ]] ; then echo sudo rm /etc/cron.daily/00logwatch ; fi

fi

echo -n "Checking install status of package LIBDATE-MANIP-PERL ..."
if [[ $statLibDateinstall == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "libdate-manip-perl"
  doPrintStatus "$?"
  #// -------------- //


fi


# The /etc/logwatch/conf directory is first searched for files with the same name and relative location as the /usr/share/logwatch/default.conf directory.
# www.stellarcore.net/logwatch/tabs/docs/HOWTO-Customize-LogWatch.html
echo -n "Copy configuration folder to working directory ..."

#// do not separate //
sudo cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/
doPrintStatus "$?"
#// -------------- //


echo -n "Backup logwatch.conf ..."

## create read-only backupfile
timestamp=$(date '+%Y-%m-%d-%H%M%S')
sudo cp /etc/logwatch/conf/logwatch.conf /etc/logwatch/conf/logwatch.conf.bkup.$timestamp
#// do not separate //
sudo chmod a-w /etc/logwatch/conf/logwatch.conf.bkup.$timestamp
doPrintStatus "$?"
#// -------------- //

# Variable to provide summarized representation of updating sysctl.conf
# if updates are successful,no errorcodes are added and value remains 0.
errorSumLGWT=0

#####
###DEBUG
#fi
#####

echo -n "Update file logwatch.conf ..."

# update senders email address, level of detail
#// do not separate //
doUpdateParameterInFile "MailFrom =" "MailFrom = $UserName" "/etc/logwatch/conf/logwatch.conf"
errorSumLGWT=$((errorSumLGWT+$?))
#// -------------- //
doUpdateParameterInFile "Detail =" "Detail = High" "/etc/logwatch/conf/logwatch.conf"
errorSumLGWT=$((errorSumLGWT+$?))
#// -------------- //

# if errors occured, replaces summed up errorcodes with an explicit one.
if [[ $errorSumLGWT != "0" ]] ; then errorSumLGWT=40 ; fi
doPrintStatus "$errorSumLGWT"


echo "Initial run of logwatch, result are sent to your terminal email:"
sudo logwatch --mailto $NOTIFICATIONEMAIL --output mail --format html --range 'between -7 days and today'

echo -n "Setup Logwatch report (Mondays at 8:00am 0 8 * * 1) ..."


#check if cronjob already exists
#// do not separate //
sudo crontab -l | grep "logwatch" >/dev/null
if [[ $? == 0 ]] ; then
echo_success # cronjob already exists for this task
else
#// do not separate //
(sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "0 8 * * 1 /usr/sbin/logwatch --mailto $NOTIFICATIONEMAIL --output mail --format html --range 'between -7 days and today' ") | sudo crontab -u root -
doPrintStatus "$?"
#// -------------- //
fi
#// -------------- //









## ==============================
## ===== SELinux - Apparmor =====


# National Security Agency (http://www.nsa.gov/research/selinux/index.shtml) (NSA) has taken Linux to the next level with the introduction of Security- Enhanced Linux (SELinux). SELinux takes the existing GNU/Linux operating system and extends it with kernel and user-space modifications to make it bullet-proof.

## Would I trust that statement?? ... [gutfeeling] ... so no installation of Apparmor planned yet


## ======================================================
## ===== Tiger and Tripwire - Audit system security =====
## Tiger: For Tiger no explicit cronjob is needed, since the package installer already sets up an hourly cronjob for tigercron to check if any Tiger-Check is scheduled for the current hour. The actual schedule is listed in file /etc/tiger/cronrc. Configuration for mailnotification etc. is stored in /etc/tiger/tigerrc
###-----
## Tripwire:


printf "%b\n" "\n\n =======~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~=======\n** PLEASE REMEMBER THE 2 PASSWORDS YOU ARE ENTERING **\n****** !THEY ARE NEEDED TO FINISH THE SETUP! *******\n =======~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~=======\n\n"
#userConfirm this message
read -r -p "Note down the Tripwire -SITE and -LOCAL Passwords! Press Enter to continue... "

#preconfigure tripwire package
# --- setting password by script not yet supported by tripwire ---
#sudo debconf-set-selections <<< 'tripwire tripwire/site-passphrase password mySitePassword'
#sudo debconf-set-selections <<< 'tripwire tripwire/site-passphrase-again password mySitePassword'
#sudo debconf-set-selections <<< 'tripwire tripwire/local-passphrase password myLocalPassword'
#sudo debconf-set-selections <<< 'tripwire tripwire/local-passphrase-again password myLocalPassword'
# --------------------

sudo debconf-set-selections <<< "tripwire tripwire/site-passphrase-incorrect boolean false"
sudo debconf-set-selections <<< "tripwire tripwire/local-passphrase-incorrect boolean false"
sudo debconf-set-selections <<< "tripwire tripwire/installed note"
sudo debconf-set-selections <<< "tripwire tripwire/use-localkey boolean true"
sudo debconf-set-selections <<< "tripwire tripwire/use-sitekey boolean true"
sudo debconf-set-selections <<< "tripwire tripwire/local-passphrase-incorrect boolean false"
sudo debconf-set-selections <<< "tripwire tripwire/rebuild-config boolean true"
sudo debconf-set-selections <<< "tripwire tripwire/rebuild-policy boolean true"
sudo debconf-set-selections <<< "tripwire tripwire/email-report note $NOTIFICATIONEMAIL"


statTigerInstall=$( isPackageInstalled "tiger" )
echo -n "Checking Install Status of package tiger ..."
if [[ $statTigerInstall == $YES ]] ; then
  echo_success

else
  #// do not separate //
  doInstall "tiger" "-forceInteraction"
  doPrintStatus "$?"
  #// -------------- //
  #remove default cronjobs since we modify them according to our needs, especially notificationemails
  if [[ -e /etc/cron.d/john ]] ; then echo sudo rm /etc/cron.d/john ; fi
  if [[ -e /etc/cron.daily/tripwire ]] ; then echo sudo rm /etc/cron.daily/tripwire ; fi
fi


# initialize database
# previously set local password is required
sudo tripwire --init
#tripwire automatically installs in cron.daily, todo remove them


# extract paths wich are not used by the system
sresult=$( sudo tripwire --check | grep Filename )
if [[ -n $srestult ]] ; then
while read -r pathitem ; do
  #remove all chars before (inclusive) ":"
  pathitem=${pathitem#*: }
  doCommentOutInFile "$pathitem" "/etc/tripwire/twpol.txt"
  echo "~~comment out: $pathitem"
done <<< "$sresult"
fi


doCommentOutInFile "/var/lock" "/etc/tripwire/twpol.txt"
doCommentOutInFile "/var/run" "/etc/tripwire/twpol.txt"


newEntries=()
newEntries+=('/dev/pts -> $(Device) ;')
newEntries+=('/proc/devices -> $(Device) ;')
newEntries+=('/proc/tty -> $(Device) ;')
newEntries+=('/proc/net -> $(Device) ;')
newEntries+=('/proc/sys -> $(Device) ;')
newEntries+=('/proc/cpuinfo -> $(Device) ;')
newEntries+=('/proc/modules -> $(Device) ;')
newEntries+=('/proc/mounts -> $(Device) ;')
newEntries+=('/proc/dma -> $(Device) ;')
newEntries+=('/proc/filesystems -> $(Device) ;')
newEntries+=('/proc/interrupts -> $(Device) ;')
newEntries+=('/proc/ioports -> $(Device) ;')
newEntries+=('/proc/scsi -> $(Device) ;')
newEntries+=('/proc/kcore -> $(Device) ;')
newEntries+=('/proc/self -> $(Device) ;')
newEntries+=('/proc/kmsg -> $(Device) ;')
newEntries+=('/proc/stat -> $(Device) ;')
newEntries+=('/proc/loadavg -> $(Device) ;')
newEntries+=('/proc/uptime -> $(Device) ;')
newEntries+=('/proc/locks -> $(Device) ;')
newEntries+=('/proc/meminfo -> $(Device) ;')
newEntries+=('/proc/misc -> $(Device) ;')

doAppendLinesToExactParameterInFile "\s*/proc *\s*\-> \$(Device) ;" newEntries[@] "/etc/tripwire/twpol.txt"

doCommentOutInFile "/proc\s" "/etc/tripwire/twpol.txt"

echo "reinit policies and tripwire db"
#update policy and reeint database
sudo twadmin -m P /etc/tripwire/twpol.txt
sudo tripwire --init


# run tripwire
sudo tripwire --check | mail -s "Tripwire Initial Report" -r "TRIPWIRE" $NOTIFICATIONEMAIL

# setup Cronjob
echo -n "Setup cronjob for tripwire (Sundays at 11pm ...) "
#check if cronjob already exists
#// do not separate //
sudo crontab -l | grep "logwatch" >/dev/null
if [[ $? == 0 ]] ; then
echo_success # cronjob already exists for this task
else
#// do not separate //
(sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "0 23 * * 7 /usr/sbin/tripwire --check | mail -s 'Tripwire weekly audit' -r 'TRIPWIRE CRON' $NOTIFICATIONEMAIL") | sudo crontab -u root -
doPrintStatus "$?"
#// -------------- //
fi
#// -------------- //





# ToDo configure tiger settings
echo -n "Setting TIGER and TIGERCRON Configuration ..."
errorSumTIG=0
#// do not separate //
doUpdateParameterInFile "Tiger_Mail_RCPT" "Tiger_Mail_RCPT=$NOTIFICATIONEMAIL" "/etc/tiger/tigerrc"
errorSumTIG=$((errorSumTIG+$?))
#// -------------- //
doUpdateParameterInFile "Tiger_Check_SENDMAIL" "Tiger_Check_SENDMAIL=N" "/etc/tiger/tigerrc"
errorSumTIG=$((errorSumTIG+$?))
#// -------------- //
doUpdateParameterInFile "Tiger_Check_DELETED" "Tiger_Check_DELETED=Y" "/etc/tiger/tigerrc"
errorSumTIG=$((errorSumTIG+$?))
#// -------------- //
doUpdateParameterInFile "Tiger_Check_PATCH" "Tiger_Check_PATCH=Y" "/etc/tiger/tigerrc"
errorSumTIG=$((errorSumTIG+$?))
#// -------------- //
doUpdateParameterInFile "Tiger_SSH_PasswordAuthentication" "Tiger_SSH_PasswordAuthentication='no'" "/etc/tiger/tigerrc"
errorSumTIG=$((errorSumTIG+$?))
#// -------------- //
#// do not separate // run for intrusion signs once a day at 11pm
doUpdateParameterInFile "check_known check_rootkit check_logfiles check_runprocs check_rootdir check_root" "23 \* \*      check_known check_rootkit check_logfiles check_runprocs check_rootdir check_root" "/etc/tiger/cronrc"
errorSumTIG=$((errorSumTIG+$?))
#// -------------- //
#ToDo: if apache installed; then Tiger_Check_APACHE=Y
doPrintStatus "$errorSumTIG"


echo "==== Starting Tiger system audit"
sudo tiger -e


# use command tigercron
# even this job will execute every hour to check if a actual tiger_check needs to run. These jobs are scheduled in /etc/tiger/cronrc
#echo -n "Setup cronjob for tigercron ..."
##// do not separate //
#(sudo crontab -l -u root 2>/dev/null ; printf "%s\n" "0 * * * * /usr/sbin/tigercrontr -E") | sudo crontab -u root -
#doPrintStatus "$?"
##// -------------- //

## ===========================
echo "please reboot"




echo "please regularly check logfiles: "
echo "/var/log/rkhunter.log"


echo -e "======= SUCCESSFUL TASKS ======= \n$OVERALLSUCCESS\n================================="

echo -e "======= FAILED TASKS ======= \n$OVERALLERROR \n============================="

