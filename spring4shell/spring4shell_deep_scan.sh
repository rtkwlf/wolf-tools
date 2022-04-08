#!/usr/bin/env sh

#
# Arctic Wolf Spring4Shell Deep Scan
# Copyright 2022, Arctic Wolf Networks, Inc.
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
printf '%s\n' "            Arctic Wolf Spring4Shell Deep Scan (CVE-2022-22965) v$version"
printf '%s\n' "--------------------------------------------------------------------------------"
printf '%s\n' "Java applications that contain a vulnerable version of the Spring Framework and"
printf '%s\n' "that are running on Java version 9 or greater may be subject to CVE-2022-22965."
printf '%s\n' ""
printf '%s\n' "For additional information including scan logic, usage instructions, output"
printf '%s\n' "examples and more, please see the README file accompanying this script and at:"
printf '%s\n' "  https://github.com/rtkwlf/wolf-tools/blob/main/spring4shell/README.md"
printf '%s\n' ""
printf '%s\n' "For remediation steps, contact the vendor of each vulnerable Java application."
printf '%s\n' "--------------------------------------------------------------------------------"
printf '%s\n' ""

scan_ts=$(date +"%Y-%m-%dT%H:%M:%S%z")
# Avoid : in filenames because windows doesn't allow them
scan_ts_fs=$(date +"%Y-%m-%dT%H.%M.%S%z")
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
  output_filepath="spring4shell_deep_scan.output.$hostname.$scan_ts_fs.json"
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
    printf '%s\n' "$(date +"%Y-%m-%dT%H:%M:%S%z") - $1 - $2" >> $log_filepath
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
  printf '%s\n' "Usage: spring4shell_deep_scan.sh [search_root [output_filepath]]"
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
# Print path of original affected spring4shell jar/war/ear.  Recursively checks.
# ARGUMENTS:
#   1: path of original toplevel archive
#   2: path of current archive to inspect
#######################################
checkarchive() {
  manifest=$( ( unzip -l "$2" 2>/dev/null || echo '_unknownjar_' ) | grep -E '(org/springframework/beans/CachedIntrospectionResults\.class|\.[ejw]ar|_unknownjar_)$')
  if printf '%s\n' "$manifest" | grep -q '_unknownjar_' ; then
    log 'WARN' "failed to read $1"
    return 1
  fi
  
  if printf '%s\n' "$manifest" | grep -q 'org/springframework/beans/CachedIntrospectionResults\.class' && printf '%s\n' "$manifest" | grep 'org/springframework/beans/CachedIntrospectionResults\.class' | awk '{print substr($0, index($0, $4))}' | xargs unzip -p "$2" | (! grep -q 'java/security/ProtectionDomain') 
  then
    if [ "$1" = "$2" ]; then
      log 'WARN' "found vulnerability in $1"
    else
      log 'WARN' "found embedded vulnerability in $1"
    fi
    printf '%s\n' "$1"
  else
    printf '%s\n' "$manifest" | grep -E '\.*[ejw]ar$' | while read -r line ; do
      printf '%s\n' "$line" | grep -E '\.[ejw]ar$' | grep -v 'Archive:' | awk '{ind = index($0, $4); if (ind > 1) print substr($0, index($0, $4))}' | while read -r subarchive; do
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


#######################################
# Log if java version is jdk9+ or unknown
# ARGUMENTS:
#   1: java path
#######################################
checkjava() {
  java_version=$("$1" -version 2>&1 || echo '_unknownjava_')
  if (printf '%s\n' "$java_version" | grep -q '_unknownjava_') || (printf '%s\n' "$java_version" | (! grep -q 'version')) ; then
    log 'WARN' "java version is unknown: $1"
  else
    if printf '%s\n' "$java_version" | head -n 1 | grep -qE '"1\.' ; then
      log 'INFO' "java $1 version: $java_version"
    else
      log 'WARN' "java jdk9+ found: $1"
    fi
  fi;
}


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


#######################################
# Print newline delimited input list of strings to stdout formatted as json
# ARGUMENTS:
#   1: list of strings
#######################################
jsonlist() {
  if [ "$1" = "" ]; then
    printf '[]' ''
    return 0
  fi
  printf '%s ' "["
  isfirst="true"
  printf '%s\n' "$1" | while read -r line; do
    escaped_line=$(escapejson "$line")
    if [ "$isfirst" = "false" ] ; then
      printf ', '
    fi
    printf '%s' "\"$escaped_line\""
    isfirst="false"
  done
  printf ' %s' ']'
}

#######################################
# Print newline delimited input list of strings to stdout as dashed list
# ARGUMENTS:
#   1: list of strings
#######################################
printlist() {
  printf '%s\n' "$1" | while read -r line; do
    printf '%s\n' "- $line"
  done
}

# Search filesystem
printf '%s\n' "Finding all Java applications under $search_root and scanning each."
printf '%s\n\n' "This can take several minutes. Ctrl-c to abort."
log 'INFO' "scanning $search_root on $hostname"
mkdir -p "tmp"
vulnjars=$(find $search_root -mount -type f \( -regex '.*\.[ejw]ar$' -o -name "java" \) 2>/dev/null | while read -r file; do
             log 'INFO' "checking $file";
             if printf '%s\n' "$file" | grep -q -E 'java$' ; then
               checkjava "$file" 
             else
               checkarchive "$file" "$file"
             fi;
           done
         )

rmdir "tmp" 2>/dev/null

# Parse results
unknownjars=$(cat "$log_filepath" | grep -E "failed to read" | awk '{print substr($0, index($0, "WARN")+22)}')
unknownjava=$(cat "$log_filepath" | grep "java version is unknown" | awk '{print substr($0, index($0, "WARN")+32)}')
java9plus=$(cat "$log_filepath" | grep 'java jdk9+ found' | awk '{print substr($0, index($0, "WARN")+25)}')

if [ "$vulnjars" = "" ]; then
  if [ "$unknownjars" = "" ]; then
    result="PASS"
    explanation='All Java applications detected were scanned and no vulnerabilities were found.'
    exit_code=0
  else
    result="UNKNOWN"
    explanation="No vulnerable Java applications were detected, but the script was not able to"
    explanation="$explanation\ndetect all scanned applications. See output and JSON for paths."
  fi
else
  if [ "$java9plus$unknownjava" = "" ]; then
    result="WARN"
    explanation="One or more vulnerable Java applications were found but Java 9+ was not found on"
    explanation="$explanation\nthe system. See output and JSON for paths. If the script was unable to scan any"
    explanation="$explanation\napplications, they will also be listed in the output and JSON."
  else
    result="FAIL"
    explanation="One or more vulnerable Java applications were found and Java 9+ was found on the"
    explanation="$explanation\nsystem. See output and JSON for paths. If the script was unable to scan any"
    explanation="$explanation\napplications, they will also be listed in the output and JSON."
    explanation="$explanation\n"
    explanation="$explanation\nNote: if vulnerable applications are found and Java is found, but the Java"
    explanation="$explanation\nversion cannot be determined, this will also result in FAIL."
    footer="For remediation steps, contact the vendor of each of the affected applications."
  fi
fi

# Output json file
printf '%s\n' '{' >> "$output_filepath"
printf '  "result": "%s",\n' "$result" >> "$output_filepath"
printf '  "hostname": "%s",\n' "$hostname" >> "$output_filepath"
printf '  "scan_ts": "%s",\n' "$scan_ts" >> "$output_filepath"
printf '  "scan_v": "%s",\n' "$version" >> "$output_filepath"
printf '  "search_root": "%s",\n' "$(escapejson "$search_root")" >> "$output_filepath"
printf '  "vulnerable_application_paths": %s,\n' "$(jsonlist "$vulnjars")" >> "$output_filepath"
printf '  "unknown_application_paths": %s,\n' "$(jsonlist "$unknownjars")" >> "$output_filepath"
printf '  "java9plus_paths": %s,\n' "$(jsonlist "$java9plus")" >> "$output_filepath"
printf '  "unknown_java_paths": %s\n' "$(jsonlist "$unknownjava")" >> "$output_filepath"
printf '%s\n' '}' >> "$output_filepath"

# Output results
log 'INFO' "Result: $result"
printf '\nResult: %s\n' "$result"
printf "$explanation\n"

if [ ! "$vulnjars" = "" ] ; then
  printf '\nVulnerable Applications:\n%s\n' "$(printlist "$vulnjars")"
fi

if [ ! "$unknownjars" = "" ] ; then
  printf '\nUnknown Applications:\n%s\n' "$(printlist "$unknownjars")"
fi

if [ ! "$java9plus" = "" ] ; then
  printf '\nJava 9+ Instances:\n%s\n' "$(printlist "$java9plus")"
fi

if [ ! "$unknownjava" = "" ] ; then
  printf '\nUnknown Java Instances:\n%s\n' "$(printlist "$unknownjava")"
fi

if [ ! "$footer" = "" ] ; then
  printf '\n%s\n' "$footer"
fi

if [ "$result" = "PASS" ]; then
  exit 0
else
  exit 1
fi

