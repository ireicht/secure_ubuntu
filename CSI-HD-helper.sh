
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


# Returnvalues and Error Codes
hlp_DUPLICATE=0


## ===== F O R M A T T I N G  of Message Output S T Y L E =====
## www.franzone.com/2008/08/25/bash-script-init-style-status-message/
## ============================================================

# Column number to place the status message
RES_COLT=$( tput cols )
RES_COL=$((RES_COLT-8))

# Command to move out to the configured column number
MOVE_TO_COL="echo -en \\033[${RES_COL}G"
# Command to set the color to SUCCESS (Green)
SETCOLOR_SUCCESS="echo -en \\033[1;32m"
# Command to set the color to FAILED (Red)
SETCOLOR_FAILURE="echo -en \\033[1;31m"
# Command to set the color back to normal
SETCOLOR_NORMAL="echo -en \\033[0;39m"

# Function to print the SUCCESS status
echo_success()
{
$MOVE_TO_COL
echo -n "["
$SETCOLOR_SUCCESS
echo -n $"  OK  "
$SETCOLOR_NORMAL
echo -n "]"
echo -ne "\r"
echo
OVERALLSUCCESS=$((OVERALLSUCCESS+1))
}

# Function to print the FAILED status message
echo_failure()
{
$MOVE_TO_COL
echo -n "["
$SETCOLOR_FAILURE
echo -n $"FAILED"
$SETCOLOR_NORMAL
echo -n "]"
echo -ne "\r"
echo
OVERALLERROR=$((OVERALLERROR+1))
}


###=======================================###
###   G E N E R I C   F U N C T I O N S   ###
###=======================================###

# request user interaction
# let user decide between yes and no
# pass on text what to confirm
# echo YES, NO represents the return value
# if invalid input, repeat question
## info: -z "$response" , check if var is empty
userConfirm()
{
if [[ $AUTOINSTALL == "YES" ]] ; then
echo "YES"
return
fi

local txt2ask="$1"
local validInput="FALSE"

while [[ $validInput != "TRUE" ]] ; do
read -r -p "$txt2ask . Confirm? [n/Y] " response
if ( [ -z "$response" ] ) || ( [ `echo $response | tr [:upper:] [:lower:]` == "y" ] ) || ( [ `echo $response | tr [:upper:] [:lower:]` == "yes" ] ) ; then

validInput="TRUE"
echo "YES"

elif ( [ `echo $response | tr [:upper:] [:lower:]` == "n" ] ) || ( [ `echo $response | tr [:upper:] [:lower:]` == "no" ] ) ; then

validInput="TRUE"
echo "NO"

else
txt2ask="ERROR: INVALID INPUT, Please use yes or no. $1"
fi

done

}

## Get installation info about requested package
## Name of requested package is stored default argument1 variable $1
## return echo strings as exit codes; YES:installed; NO:not installed
# please do not add any additonal echo commands
isPackageInstalled()
{
local packageInfo=$( dpkg -s $1 2>/dev/null | grep Status )

if [[ $packageInfo == *"install ok installed"* ]] ; then
echo "YES"

else
echo "NO"
fi

}

## Do installation of requested package.
## $1: Name of requested package
## Option for autoinstall without user-interaction can be set by calling this script by argument "-y"
doInstall()
{
local doesConfirm=$(userConfirm "Please confirm installation of package $1")

# cuz tripwire does not support automated configuration of passwords, we make sure that installationscript will not halt
local verbosityForInstall=$VERBOSITY
if [[ "$2" == "-forceInteraction" ]] ; then verbosityForInstall=1 ; fi
# ---end of fix----

if [[ $doesConfirm == "YES" ]] ; then
  if [[ $verbosityForInstall == 0 ]] ; then
    sudo apt-get install $1 -y >/dev/null
  else
    sudo apt-get install $1 -y
  fi

  local hasInstallError=$?
return $hasInstallError

else
# error code for not installing package
return 13
fi


}
# ToDo Comments
## in terms of readabilty and maintanance, this commenting function is written explicitely and was not merged into the function "doUpdateInFile"
doCommentOutInFile()
{
local valueOfInterest="$1"
local filePath="$2"

# make sure passed on file exists
if [[ ! -s $filePath ]] ; then
echo "file $filePath does not exists or seems to be invalid"
return 30

fi

# reduce search space to enabled lines, and get list of linenumbers
local listOfLines=$( grep -n "^[^#]*$valueOfInterest" $filePath | sed -n 's/^\([0-9]*\)[:].*/\1/p' )


# commented out all matching lines
if [[ -n $listOfLines ]] ; then

while read -r lineNr ; do
local lineVal=$( sed -n "$lineNr p" $filePath )
local commentLineVal="# $lineVal # $(date '+%Y-%m-%d %H:%M:%S'): $SCRIPTNAME"
local contentOut=$( sed -e "$lineNr a $commentLineVal" -e "$lineNr d" $filePath )
printf '%s\n' "$contentOut" > $filePath

done <<< "$listOfLines"
fi

# Sanity check to make sure file did not get corrupted by updating parameters
if [[ ! -s $filePath ]] ; then
echo "[ERROR]: While updating file $filePath with $valueOfInterest and $newValue, something went terribly woring. The file does not exist anymore or is now invalid."
return 31
fi

}

# This method updates parameters with a new value. The replacement is performed linewise.
# All lines matching the search pattern will be commented out and the line with the updated parameters will be added. By default, already commented out lines will not be processed. If no matches are found, the new value will be added at the end of the file
###
# parameter1: search pattern; e.g. "Port"
# parameter2: new Parameter; e.g. "Port 1022"
# parameter3: Path to File; e.g. "/etc/ssh/sshd_config"
# parameter4: Flags for control; -gd: (grep disabled lines) - also include disabled lines into searchspace
##
# please make sure you perform a backup of the desired file before passing it to this method
# be aware using "" as search pattern, this will cause to comment out the whole file
# also char * in searchpattern does not work. However, new Parameter can contain *
##
# note: multiple active entries of the same key/value schould not occur in config files. Therefore this method is commenting out all but one lines matching the search-pattern "$valueOfInterest"; if so, please use simple find and replace methods instead.

doUpdateParameterInFile()
{
local valueOfInterest="$1"
local newValue="$2"
local filePath="$3"
local controlArg="$4"

# stores all matching linenumbers
local listOfLines=""
# stores the linenumber which is going to be replaced
local lineToReplace=""

# make sure passed on file exists
if [[ ! -s $filePath ]] ; then
echo "file $filePath does not exists or seems to be invalid"
return 30

fi

### Regex explanation:
## ^     refers to the beginning of the line
## [# ]  refers to any character wich are "#" and " "
## [^#]  refers to any character which is not "#"
## Sed's RegEx explanation:
## The -n means not to print anything unless it's explicitly requested.
## s - substitute
## / - beginning of patter to match
## ^ - The null character at the start of the line
## \(....\) - store this in the pattern buffer
## [0-9]* - match any number of occurrences numbers in the range 0-9
## [:] - match the ":" character
## .* - match any number of any characters (the rest of the line)
## / - end on the match patter and beginning on the replace pattern
## \1 - the first entry in the pattern buffer ( what was stored with \(...\) )
## / - end of the replace pattern
## p - print
###


# check if new key/value is activated and set exactly 1 time, then no further processing needed.
# patternOccurances check is needed to make sure, that $valueOfInterest is not enabled multiple times (to avoid that $newValue is overwritten somewhere later in the config file)
local newValueAlreadySet=$( grep -c "^[^#]*$newValue" $filePath )
local patternOccurances=$( grep -c "^[^#]*$valueOfInterest" $filePath )
if (( $newValueAlreadySet == 1 && $patternOccurances <= 1 )) ; then
  echo "~~newValue already set $newValue"
  return $hlp_DUPLICATE
fi


# search in all enabled lines for the provided search pattern, ignore commented out lines (see Regex below), and store line numbers as result.
if [[ $controlArg == "-gd" ]] ; then
  listOfLines=$( grep -nr "^[# ]*$valueOfInterest" $filePath | sed -n 's/^\([0-9]*\)[:].*/\1/p' )

else
  listOfLines=$( grep -nr "^[^#]*$valueOfInterest" $filePath | sed -n 's/^\([0-9]*\)[:].*/\1/p' )
#    echo "listOfLines norm: $listOfLines"
fi


# commented out all matching lines
if [[ -n $listOfLines ]] ; then

  while read -r lineNr ; do
    local lineVal=$( sed -n "$lineNr p" $filePath )
    local commentLineVal="# $lineVal"
    local contentOut=$( sed -e "$lineNr a $commentLineVal" -e "$lineNr d" $filePath )
    printf '%s\n' "$contentOut" > $filePath

  done <<< "$listOfLines"
fi

# Adding/replacing values
# if no lines to replace, then add them to the end of the provided file.
if [[  -z $listOfLines ]] ; then
# add line at the end of the file
printf '%s\n' "# $(date '+%Y-%m-%d %H:%M:%S'): $SCRIPTNAME adding new entry " >> $filePath
printf '%s\n' "$newValue" >> $filePath

else
# if multiple lines match, only replace one line.
# take the first entry of listOfLines
read -r lineToReplace <<< "$listOfLines"

# replace the matching line with the desired value
local oldValue=$( sed -n "$lineToReplace p" $filePath )
local contentNew=$( sed -e "$lineToReplace a # $(date '+%Y-%m-%d %H:%M:%S'): replaced: $oldValue with: $newValue" -e "$lineToReplace a $newValue" -e "$lineToReplace d" $filePath )
printf '%s\n' "$contentNew" > $filePath

fi


# Sanity check to make sure file did not get corrupted by updating parameters
if [[ ! -s $filePath ]] ; then
echo "[ERROR]: While updating file $filePath with $valueOfInterest and $newValue, something went terribly woring. The file does not exist anymore or is now invalid."
return 31
fi

}

##
# search for an exact pattern, then add desired new parameters as new lines below
# this method only processes, if grep of pattern returns exactly 1 match
##
# $1: Search pattern
# $2: Array of lines to add
# $3: Path to file
# $4: Options, -stack means that the passed array of lines will be added BEFORE the line of the matching search pattern
##
doAppendLinesToExactParameterInFile()
{

local valueOfInterest=$1
declare -a newLinesArray=("${!2}")
local filePath=$3

local matchingLine=$( grep -x -n "^[^#]*$valueOfInterest" $filePath | sed -n 's/^\([0-9]*\)[:].*/\1/p' )
local nrOfMatches=$( grep -x -c "^[^#]*$valueOfInterest" $filePath )
echo $matchingLine

if [[ $nrOfMatches != 1 ]] ; then echo "incompatible amount of matches: $nrOfMatches"; return 2; fi

if [[ "$4" == "-stack" ]] ; then
  matchingLine=$((matchingLine-1))
fi


## compile checksum of given arguments to check if this method was already called before
local allArgs=$valueOfInterest
for lineArgs in "${newLinesArray[@]}" ; do
  allArgs=$allArgs$lineArgs
#  echo "$allArgs"
done

local compiledChecksum=$( echo -n "$allArgs" | sha1sum )
local foundChecksum=$( grep -c "$compiledChecksum" $filePath )
echo "inside method"  >> output.txt
if [[ "$foundChecksum" != "0" ]] ; then echo "~~parameters already available in file"; return 3; fi
# add checksum to the array as a comment
newLinesArray+=("# $SCRIPTNAME extension checksum $compiledChecksum")
####


#echo $matchingLine
for newLine in "${newLinesArray[@]}" ; do
  if (( $matchingLine <= 0 )) ; then #sed -i -e "lineNr a $newline" cannot be executen when lineNr==0
  	sed -i "1i$newLine" $filePath
  	#sed -i "1i# $SCRIPTNAME" $filePath # insert comment line
  else
    #sed -i -e "$matchingLine a # $SCRIPTNAME" $filePath # insert comment line
    sed -i -e "$matchingLine a $newLine" $filePath
  fi

done

  

}




doPrintStatus()
{
if [[ "$1" == "0" ]] ; then
echo_success
else
echo -n "..ERROR CODE: $1 .."
echo_failure
fi

# this sleep is only for better user experience while monitoring the progress of the script.
sleep 0.2
}
