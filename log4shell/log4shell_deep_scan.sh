#!/usr/bin/env sh

#
# Arctic Wolf Log4Shell Deep Scan
# Copyright 2021, Arctic Wolf Networks, Inc.
# 
# Arctic Wolf Networks, Inc. licenses this file to you under the Apache License,
# Version 2.0 (the "License").  You may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0.
# 
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.    
#

version='0.3'
logging='on'

printf '%s\n' ""
printf '%s\n' "--------------------------------------------------------------------------------"
printf '%s\n' "Arctic Wolf Log4Shell Deep Scan (CVE-2021-44228, CVE-2021-45046) v$version"
printf '%s\n' "--------------------------------------------------------------------------------"
printf '%s\n' "This script searches the system for Java applications that contain the Log4J"
printf '%s\n' "class JndiLookup.class which is the source of the Log4Shell vulnerabilities. If"
printf '%s\n' "this class is found within an application, the script looks for updates to the"
printf '%s\n' "to Log4J that indicate the application has been updated to use Log4J 2.16+ or"
printf '%s\n' "Log4J 2.12.2+. If the application contains JndiLookup.class but does not appear"
printf '%s\n' "to have been updated, the application is vulnerable."
printf '%s\n' ""
printf '%s\n' "For additional information and usage please see the readme.txt."
printf '%s\n' "--------------------------------------------------------------------------------"
printf '%s\n' ""

scan_ts=$(date +%s)
hostname="$(hostname)"

# Parse arguments

# 1: search root location or /
search_root="$1"
if [ "$search_root" = "" ]; then
  search_root="/"
fi

# 2: output json file location or default
output_filepath="$2"
if [ "$output_filepath" = "" ]; then
  output_filepath="log4shell_deep_scan.output.$hostname.$scan_ts.json"
fi

# set log location to output path but .log
if command -v sed > /dev/null
then
  log_filepath=$(printf '%s' "$output_filepath" | sed 's/json$/log/g')
else
  log_filepath="${output_filepath//.json/.log}"
fi
# if custom output_filepath has non json extension then add .log so filepath unique
if [ "$output_filepath" = "$log_filepath" ]; then
  log_filepath=$(printf '%s.log' "$log_filepath")
fi

#######################################
# Append log message to global $log_filepath
# ARGUMENTS:
#   1: level
#   2: message
#######################################
log ()
{
  if [ "$logging" = "on" ] ; then
    printf '%s\n' "$(date +%s) - $1 - $2" >> $log_filepath
  fi
}

# if output file exists, warn and quit
if [ -e "$output_filepath" ]; then
    printf '%s\n' "ERROR: output file exists. Please delete $output_filepath or specify an alternate output file."
  exit 2
fi

# if log file exists, warn and quit
if [ -e "$log_filepath" ]; then
    printf '%s\n' "ERROR: log file exists. Please delete $log_filepath or specify an alternate log file."
  exit 2
fi

# if search root doesn't exist, warn and quit
if [ ! -e "$search_root" ]
then
  printf '%s\n' "Usage: log4shell_deep_scan.sh [search_root [output_filepath]]"
  printf '%s\n' "ERROR: $search_root doesn't exist. Please specify an alternate scan path."
  exit 2
fi

# Log environment information for debugging
log 'INFO' "Command-line arguments: '$1' '$2'"
log 'INFO' "Version: $version"
log 'INFO' "Operating System: $(uname -a)"

# Check dependencies

if ! command -v unzip > /dev/null; then
  printf '%s\n' "unzip command not found"
  printf '%s\n' "Result: UNKNOWN missing script dependency unzip"
  exit 2
fi

if ! command -v mktemp > /dev/null; then
  printf '%s\n' "mktemp command not found"
  printf '%s\n' "Result: UNKNOWN missing script dependency mktemp"
  exit 2
fi


#######################################
# Print path of original affected log4shell jar/war/ear.  Recursively checks.
# ARGUMENTS:
#   1: path of original toplevel archive
#   2: path of current archive to inspect
#######################################
checkarchive() {
  manifest=$( ( unzip -l "$2" 2>/dev/null || echo '_unknownjar_' ) | grep -E '(Jndi.*\.class|\.[nejw]ar|_unknownjar_)$')
  # added n for NiFi nar files
  if printf '%s\n' "$manifest" | grep -q '_unknownjar_' ; then
    log 'WARN' "failed to read $1"
    return 1
  fi
  
  if printf '%s\n' "$manifest" | grep -q "JndiLookup.class" && printf '%s\n' "$manifest" | grep "JndiManager.class" | awk '{print substr($0, index($0, $4))}' | xargs unzip -p "$2" | (! grep -q 'log4j2.enableJndi') 
  then
    if [ "$1" = "$2" ]; then
      log 'WARN' "found vulnerability in $1"
    else
      log 'WARN' "found embedded vulnerability in $1"
    fi
    printf '%s\n' "$1"
  else
    # awk '{ind = index($0, $4); if (ind > 1) print substr($0, index($0, $4))}'
    printf '%s\n' "$manifest" | grep -E '\.*[nejw]ar$' | while read -r line ; do
      printf '%s\n' "$line" | grep -E '\.[nejw]ar$' | awk '{ind = index($0, $4); if (ind > 1) print substr($0, index($0, $4))}' | while read -r subarchive; do
        log 'INFO' "found $subarchive in $1"
        extract_path=$(mktemp "tmp/tmp-XXXXXX")
        unzip -p "$2" "$subarchive" 2>/dev/null > "$extract_path" || log 'WARN' "failed to read $1"
        log 'INFO' "checking $file"
        output=$(checkarchive "$1" "$extract_path")
        rm "$extract_path"
        
        # Vulnerable nested jar stop recursing
        if ! [ "$output" = "" ] ; then
          printf '%s\n' "$output"
          return 6
        fi;
      done
      if [ "$?" = "6" ] ; then
        return 6
      fi
    done
  fi
}


printf '%s\n' "Finding all JAR files under $search_root and scanning each."
printf '%s\n\n' "This can take several minutes. Ctrl-c to abort."
log 'INFO' "scanning $search_root on $hostname"
mkdir -p "tmp"
output=$(find "$search_root" -mount -type f -regex '.*\.[nejw]ar$' 2>/dev/null | while read -r file; do log 'INFO' "checking $file"; checkarchive "$file" "$file"; done)
rmdir "tmp" 2>/dev/null


#######################################
# Portable function to escape " and \ in json strings
# ARGUMENTS:
#   1: string to escape
#######################################
escapejson() {
  if command -v sed > /dev/null
  then
    printf '%s' "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g'
  else
    escaped="${1//\\/\\\\}"
    printf '%s\n' "${escaped//\"/\\\"}"
  fi
}

# Output results

escaped_search_root=$(escapejson "$search_root")
printf '%s\n' ""


unknownjars=$(cat "$log_filepath" | grep -E "failed to read" | awk '{print substr($0, index($0, "WARN")+22)}')


if [ "$output" = "" ] ; then
  if [ "$unknownjars" = "" ] ; then
  
    log 'INFO' 'Result: PASS'
    printf '%s\n' "Result: PASS"
    printf '%s\n' "No Java applications containing Log4j JndiLookup were found."
  
    printf '%s\n' "[" >> "$output_filepath"
    printf '%s\n' "  { \"hostname\":\"$hostname\", \"scan_ts\":\"$scan_ts\", \"scan_v\":\"0.2\", \"search_root\":\"$escaped_search_root\", \"result\":\"PASS\", \"vulnerable_jar\":false }" >> "$output_filepath"
    printf '%s\n' "]" >> "$output_filepath"
    exit 0
  else
    log 'INFO' 'Result: UNKNOWN'
    printf '%s\n' "Result: UNKNOWN"
    printf '%s\n' "No Java applications containing unpatched Log4j were found, but the following"
    printf '%s\n\n' "applications were not readable by this detection script:"
    
    printf '%s\n' "$unknownjars" | while read -r line; do
      printf '%s\n' "- $line"
    done
    
    printf '%s\n' "[" > "$output_filepath"
    isfirst="true"
    printf '%s\n' "$unknownjars" | while read -r line; do
      escaped_jar=$(escapejson "$line")
      if [ "$isfirst" = "false" ] ; then
        printf ',\n' >> "$output_filepath"
      fi
      printf '%s' "  { \"hostname\":\"$hostname\", \"scan_ts\":\"$scan_ts\", \"scan_v\":\"0.2\", \"search_root\":\"$escaped_search_root\", \"result\":\"UNKNOWN\", \"unscanned_jar\":\"$escaped_jar\" }" >> "$output_filepath"
      isfirst="false"
    done
    
    printf '\n%s\n\n' ']' >> "$output_filepath"    
    
    exit 1
  fi
else
  log 'INFO' 'Result: FAIL'
  printf '%s\n' "Result: FAIL"
  printf '%s\n' "The following Java applications contain Log4j JndiLookup, do not appear to have"
  printf '%s\n' "been updated to Log4J 2.16+, and are likely subject to Log4Shell"
  printf '%s\n' "(CVE-2021-44228, CVE-2021-45046)."
  printf '%s\n' ""
  printf '%s\n' "[" > "$output_filepath"
  isfirst="true"
  printf '%s\n' "$output" | while read -r line; do
    printf '%s\n' "- $line"
    escaped_jar=$(escapejson "$line")
    if [ "$isfirst" = "false" ] ; then
      printf ',\n' >> "$output_filepath"
    fi
    printf '%s' "  { \"hostname\":\"$hostname\", \"scan_ts\":\"$scan_ts\", \"scan_v\":\"0.2\", \"search_root\":\"$escaped_search_root\", \"result\":\"FAIL\", \"vulnerable_jar\":\"$escaped_jar\" }" >> "$output_filepath"
    isfirst="false"
  done
  
  if [ ! "$unknownjars" = "" ] ; then
    printf ',\n' '%s' >> "$output_filepath"
  
    printf '%s\n' "$unknownjars" | while read -r line; do
      if [ ! "$line" = "" ] ; then
        escaped_jar=$(escapejson "$line")
        if [ "$isfirst" = "false" ] ; then
          printf ',\n' >> "$output_filepath"
        fi
        printf '%s' "  { \"hostname\":\"$hostname\", \"scan_ts\":\"$scan_ts\", \"scan_v\":\"0.2\", \"search_root\":\"$escaped_search_root\", \"result\":\"UNKNOWN\", \"unscanned_jar\":\"$escaped_jar\" }" >> "$output_filepath"
        isfirst="false"
      fi
    done
  fi
  
  printf '\n%s\n\n' ']' >> "$output_filepath"
  
  if [ ! "$unknownjars" = "" ] ; then
    printf '\n%s\n' "WARNING"
    printf '%s\n\n' "The following applications were not readable by this detection script:"
  
    printf '%s\n' "$unknownjars" | while read -r line; do
      printf '%s\n' "- $line"
    done
  fi
  
  printf '%s\n' ""
  printf '%s\n' "For remediation steps, contact the vendor of each of the affected applications."
  printf '%s\n' ""
  exit 1
fi
