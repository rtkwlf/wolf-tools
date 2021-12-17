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
param (
    [string]$search_root = "",
    [string]$output_filepath = "",
    [string]$log_filepath = ""
)

# Constants

# set to $false to disable loggin
$LOGGING = $true

#
# String Functions
#

function Escape-JSON($s) {
  return $s.replace('\','\\').replace('"','\"')
}

function Escape-FilePath($s) {
  return $s -replace "[^a-zA-Z0-9.-]", "_"
}

#
# IMPORTS, PARAMs
#

# clear all errors, add compression
$error.Clear()
Add-Type -AssemblyName "System.IO.Compression"

# globals
$scan_ts = $(Get-Date -format 'o')
$hostname = [System.Net.Dns]::GetHostName()
$vulnerable_java_apps = @()
$unreadable_java_apps = @()
$Mutex = New-Object System.Threading.Mutex

# default output_path and validate 
if (!$output_filepath) {
  $output_filepath = "log4shell_deep_scan.output.$(Escape-FilePath $hostname).$(Escape-FilePath $scan_ts).json"
}
if (Test-Path $output_filepath) {
  Write-Output "ERROR: output file exists. Please delete $output_filepath or specify an alternate output filepath."
  exit 0
}

# default log_path and validate 
if (!$log_filepath) {
  $log_filepath = $output_filepath -replace "\.json$", ".log"
}
if (Test-Path $log_filepath) {
  Write-Output "ERROR: log file exists. Please delete $log_filepath or specify an alternate log filepath."
  exit 0
}

# default search_root, ensure it is an array
if ($search_root) {
  $search_roots = @($search_root)
} else {
  $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object {$_.DriveType -eq 'Fixed' } | Select-Object RootDirectory
  $search_root = ($drives | Select-Object -ExpandProperty RootDirectory)
  $search_roots = @($drives | Select-Object -ExpandProperty RootDirectory)
}
$search_root_escaped = Escape-JSON "$search_root"

#
# Functions
#

function Write-Log($Level, $Message) {
  if ($LOGGING) {
    $Temp = "{0} - {1} - {2}" -f $(Get-Date -format 'o'), $Level, $Message
    try {
      while(!$script:Mutex.WaitOne()) {
        Start-Sleep -m 100
      }
      try {
        $Temp | Out-File $log_filepath -Append
      } finally {
        $script:Mutex.ReleaseMutex()
      }
    } catch {
      Write-Warning $("Failed to write message {0} to log file: {1}" -f $Temp, $_.Exception.Message)
    }
  }
}

function Check-Archive {
  param (
    [String]$Path=$(throw "Mandatory parameter -Path"),
    [System.IO.Stream]$Stream=$(throw "Mandatory parameter -Stream")
  )
  Write-Log 'INFO' "checking $Path"
  $Archive = New-Object System.IO.Compression.ZipArchive $Stream
  try {
    # iterate over jar contents
    $found_jndilookup_class = $false
    $found_patched_indicator = $false
    foreach ($Entry in $Archive.Entries) {
      if ($Entry.Name -eq "JndiLookup.class") {
        # jar contains JndiLookup.class which is the source of vulnerabilitiess
        $found_jndilookup_class = $true
      } elseif ($Entry.Name -eq "JndiManager.class") {
        # read JndiManager.class and search for log4j2.enableJndi
        try {
          $reader = New-Object System.IO.StreamReader $Entry.Open()
          $found_patched_indicator = $($reader.ReadToEnd() | Select-String -Pattern "log4j2.enableJndi" -Quiet) -eq $True
        } catch {
          $script:unreadable_java_apps += $Path
          Write-Log 'WARN' $("failed to read: {0}!{1}: {2}" -f $Path, $Entry.Name, $_.Exception.Message)
        } finally {
          # Need the checks since we don't know where the try statements might fail
          if ($reader){
              $reader.Close()
          }
        }
      } elseif ($Entry.Name -match "\.(war|ear|jar)$") {
        # nested .war/ear/jar, recurse inside this entry
        Check-Archive -Path $("{0}!{1}" -f $Path, $Entry.Name) -Stream $Entry.Open()
      }
    }
    # is jar vulnerable?
    if ($found_jndilookup_class -and ($found_patched_indicator -eq $null -or !$found_patched_indicator)) {
      Write-Log 'WARN' $("Vulnerable JAR: {0}" -f $Path)
      $script:vulnerable_java_apps += $Path
    }
  } catch {
    $script:unreadable_java_apps += $Path
    Write-Log 'WARN' $("failed to read {0}: {1}" -f $Path, $_.Exception.Message)
  } finally {
    $Stream.Close()
    if ($Archive) {
      $Archive.Dispose()
    }
  }
}

#
# Write Header
#

Write-Output  @"
------------------------------------------------------------------------------
Arctic Wolf Log4Shell Deep Scan (CVE-2021-44228, CVE-2021-45046) v0.3
------------------------------------------------------------------------------
This script searches the system for Java applications that contain the Log4J
class JndiLookup.class which is the source of the Log4Shell vulnerabilities. If
this class is found within an application, the script looks for updates to the
to Log4J that indicate the application has been updated to use Log4J 2.16+ or
Log4J 2.12.2+. If the application contains JndiLookup.class but does not appear
to have been updated, the application is vulnerable.

For additional information and usage please see the readme.txt.
------------------------------------------------------------------------------

Finding all JAR files under $search_roots and scanning each.
This can take several minutes. Ctrl-c to abort.

"@

#
# SCAN search_roots and analyze jars
#

try {
  # log start
  Write-Log 'INFO' "scanning $search_roots on $hostname"
  Write-Log 'INFO' "Powershell Version: $($PSVersionTable.PSVersion.ToString())"
  Write-Log 'INFO' "Windows $([System.Environment]::OSVersion.Version.ToString())"

  # iterate across search roots, calling Check-Archive for each java app
  $search_roots | 
  ForEach-Object {Get-ChildItem -Path $_ -ErrorAction SilentlyContinue -Force -Recurse} | 
  Where-Object {!$_.PSIsContainer -and (".jar",".war",".ear") -contains $_.extension} | 
  ForEach-Object {
    # we found a jar/war/ear, let's check it!
    try {
      $Path = $_.FullName
      $Stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open)
      Check-Archive -Path $Path -Stream $Stream
    } catch {
      if (-Not ($Path -match '\\\$Recycle\.Bin\\')) {
        $script:unreadable_java_apps += $Path
        Write-Log 'WARN' $("failed to read {0}: {1}" -f $Path, $_.Exception.Message)
      }
    }
  }
} catch {
  Write-Log 'ERROR' $_
  Write-Output $_
  Write-Output "Result: ERROR"  
  exit 1
}

#
# Output Results
#

if ($vulnerable_java_apps.Length -gt 0) {
  # fail

  Write-Log 'INFO' 'Result: FAIL'
  Write-Output @"

Result: FAIL
The following Java applications contain Log4j JndiLookup, do not appear to have
been updated to Log4J 2.16+ or Log4J 2.12.2+, and are likely subject to 
Log4Shell (CVE-2021-44228, CVE-2021-45046).

"@    

  $i = 0
  $json_string = "["
  foreach ($jndi_jar in $vulnerable_java_apps) {
      $i += 1
      Write-Output "- $jndi_jar"
      $jndi_jar_escaped = Escape-JSON $jndi_jar
      $json_string += "`n  { `"hostname`":`"$hostname`", `"scan_ts`":`"$scan_ts`", `"scan_v`":`"0.2`", `"search_root`":`"$search_root_escaped`", `"result`":`"FAIL`", `"vulnerable_jar`":`"$jndi_jar_escaped`" }"
      if ($i -lt $vulnerable_java_apps.length) {
          $json_string += ','
      }
  }

  if ($unreadable_java_apps) {
    Write-Output "`nWARNING`nThe following applications were not readable by this detection script:`n"
    $json_string += ','
    $i = 0
    foreach ($unreadable_jar in $unreadable_java_apps) {
      $i += 1
      Write-Output "- $unreadable_jar"
      $unreadable_jar_escaped = Escape-JSON $unreadable_jar
      $json_string += "`n  { `"hostname`":`"$hostname`", `"scan_ts`":`"$scan_ts`", `"scan_v`":`"0.2`", `"search_root`":`"$search_root_escaped`", `"result`":`"UNKNOWN`", `"unscanned_jar`":`"$unreadable_jar_escaped`" }"
      if ($i -lt $unreadable_java_apps.length) {
          $json_string += ','
      }
    }
  }

  $json_string += "`n]"
  $json_string | Out-File "$output_filepath"

  Write-Output ""
  Write-Output "For remediation steps, contact the vendor of each affected application."
  exit 1

} elseif ($unreadable_java_apps) {
  Write-Log 'INFO' 'Result: UNKNOWN'
  Write-Output @"
Result: UNKNOWN
No Java applications containing unpatched Log4j were found, but the following
applications were not readable by this detection script:

"@

  $i = 0
  $json_string = "["
  foreach ($unreadable_jar in $unreadable_java_apps) {
    $i += 1
    Write-Output "- $unreadable_jar"
    $unreadable_jar_escaped = Escape-JSON $unreadable_jar
    $json_string += "`n  { `"hostname`":`"$hostname`", `"scan_ts`":`"$scan_ts`", `"scan_v`":`"0.2`", `"search_root`":`"$search_root_escaped`", `"result`":`"UNKNOWN`", `"unscanned_jar`":`"$unreadable_jar_escaped`" }"
    if ($i -lt $unreadable_java_apps.length) {
        $json_string += ','
    }
  }
  $json_string += "`n]"
  $json_string | Out-File "$output_filepath"

  exit 1
} else {
  Write-Log 'INFO' 'Result: PASS'
  Write-Output @"

Result: PASS
No Java applications containing unpatched Log4j were found.

"@

  "[`n  { `"hostname`":`"$hostname`", `"scan_ts`":`"$scan_ts`", `"scan_v`":`"0.2`", `"search_root`":`"$search_root_escaped`", `"result`":`"PASS`", `"vulnerable_jar`":false } `n]" | Out-File "$output_filepath"

  if ($unreadable_java_apps) {
    Write-Output "WARNING`nThe following applications were not readable by this detection script:`n`n"
    foreach ($unreadable_jar in $unreadable_java_apps) {
      Write-Output "- $unreadable_jar"
    }
  }
  exit 0
}
