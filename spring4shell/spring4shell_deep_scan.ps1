<#
  Arctic Wolf Spring4Shell Deep Scan
  Copyright 2022, Arctic Wolf Networks, Inc.

  Arctic Wolf Networks, Inc. licenses this file to you under the Apache License,
  Version 2.0 (the "License").  You may not use this file except in compliance
  with the License.  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0.

  Unless required by applicable law or agreed to in writing, software distributed
  under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
  CONDITIONS OF ANY KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations under the License.  
#>

<#
  .SYNOPSIS
  Scans system for Java applications that may be subject to CVE-2022-22965. 
  
  .DESCRIPTION
  For additional information including scan logic, usage instructions, output
  examples and more, please see the README file accompanying this script and at:
  https://github.com/rtkwlf/wolf-tools/blob/main/spring4shell/README.md

  .PARAMETER search_root
  Specifies a search_root. By default, all fixed drives will be searched. 

  .PARAMETER output_filepath
  Specifies the name and path for the JSON output file. By default,
  the file will be saved to the CWD with the name:
    spring4shell_deep_scan.output.<HOSTNAME>.<DATETIME>.json

  .PARAMETER log_filepath
  Specifies the name and path for the log file. By default, the file 
  will be saved to the CWD and the file name will match the JSON output
  file name with the extension changed from .json to .log.

  .EXAMPLE
  # open Command (cmd.exe) as administrator and run
  > powershell -ExecutionPolicy ByPass -f spring4shell_deep_scan.ps1

  .EXAMPLE
  # open Command (cmd.exe) as administrator and run
  > powershell -ExecutionPolicy ByPass -f spring4shell_deep_scan.ps1 -output_filepath FILENAME_HERE.json
#>

param (
    [string]$search_root = "",
    [string]$output_filepath = "",
    [string]$log_filepath = ""
)

# Constants

# set to $false to disable loggin
$LOGGING = $true
$error_encountered = $false

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
$vulnerable_java_executables = @()
$unreadable_java_executables = @()
$vulnerable_java_apps = @()
$unreadable_java_apps = @()
$Mutex = New-Object System.Threading.Mutex

# default output_path and validate 
if (!$output_filepath) {
  $output_filepath = "spring4shell_deep_scan.output.$(Escape-FilePath $hostname).$(Escape-FilePath $scan_ts).json"
}
if (Test-Path $output_filepath) {
  Write-Output "ERROR: output file exists. Please delete $output_filepath or specify an alternate output filepath."
  exit 1
}

# default log_path and validate 
if (!$log_filepath) {
  $log_filepath = $output_filepath -replace "\.json$", ".log"
}
if (Test-Path $log_filepath) {
  Write-Output "ERROR: log file exists. Please delete $log_filepath or specify an alternate log filepath."
  exit 1
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
    $found_unpatched_indicator = $false
    foreach ($Entry in $Archive.Entries) {
      if ($Entry.FullName -eq "org/springframework/beans/CachedIntrospectionResults.class") {
        # read "org/springframework/beans/CachedIntrospectionResults.class" and search for java/security/ProtectionDomain
        try {
          $reader = New-Object System.IO.StreamReader $Entry.Open()
          $found_unpatched_indicator = $($reader.ReadToEnd() | Select-String -Pattern "java/security/ProtectionDomain" -Quiet) -eq $Null
        } catch {
          $script:unreadable_java_apps += $Path
          Write-Log 'WARN' $("failed to read: {0}!{1}: {2}" -f $Path, $Entry.Name, $_.Exception.Message)
        } finally {
          # Need the checks since we don't know where the try statements might fail
          if ($reader){
              $reader.Close()
          }
        }
        break
      } elseif ($Entry.Name -match "\.(war|ear|jar)$") {
        # nested .war/ear/jar, recurse inside this entry
        Check-Archive -Path $("{0}!{1}" -f $Path, $Entry.Name) -Stream $Entry.Open()
      }
    }
    # is jar vulnerable?
    if ($found_unpatched_indicator -eq $True) {
      Write-Log 'WARN' $("Vulnerable application: {0}" -f $Path)
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
--------------------------------------------------------------------------------
            Arctic Wolf Spring4Shell Deep Scan (CVE-2022-22965) v0.3
--------------------------------------------------------------------------------
Java applications that contain a vulnerable version of the Spring Framework and
that are running on Java version 9 or greater may be subject to CVE-2022-22965.

For additional information including scan logic, usage instructions, output
examples and more, please see the README file accompanying this script and at:

  https://github.com/rtkwlf/wolf-tools/blob/main/spring4shell/README.md

For remediation steps, contact the vendor of each vulnerable Java application.
--------------------------------------------------------------------------------


Finding all Java applications under $search_roots and scanning each.
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
  ForEach-Object {Get-ChildItem -Path $_ -ErrorAction SilentlyContinue -Force -Recurse -Include *.jar, *.war, *.ear, java.exe } | 
  Where-Object {!$_.PSIsContainer } | 
  ForEach-Object {
    # we found a jar/war/ear file or java.exe, let's check it!
    if ($_.FullName -match ".*java.exe$") {
      try {
        $Path = $_.FullName
        Write-Log 'INFO' "checking $Path"
        [array] $cmdOutput = . $Path "-version" 2>&1
        Write-Log 'INFO' $("Found java version: {0}" -f $cmdOutput[0])
        # is java vulnerable?
        if (-Not ($cmdOutput[0] -match "`"1\.")) {
          Write-Log 'WARN' $("Vulnerable JAVA Executable: {0}" -f $Path)
          $script:vulnerable_java_executables += $Path
        }
      } catch {
        if (-Not ($Path -match '\\\$Recycle\.Bin\\')) {
          $script:unreadable_java_executables += $Path
          Write-Log 'WARN' $("failed to read {0}: {1}" -f $Path, $_.Exception.Message)
        }
      }
    }
    else {
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
  }
} catch {
  Write-Log 'ERROR' $_
  Write-Log 'Scan aborted due to error'
  Write-Output 'ERROR' $_
  Write-Output 'Scan aborted due to error'
  $error_encountered=$true
}

#
# Output Results
#

if ($error_encountered -eq $false -and $unreadable_java_apps.Length -eq 0 -and $vulnerable_java_apps.Length -eq 0) {
  $result="PASS"
} elseif ($error_encountered -eq $false -and $vulnerable_java_apps.Length -gt 0 -and ($vulnerable_java_executables.Length -gt 0 -or $unreadable_java_executables.Length -gt 0)) {
  $result="FAIL"
} elseif ($error_encountered -eq $false -and $vulnerable_java_apps.Length -gt 0 -and $vulnerable_java_executables.Length -eq 0 -and $unreadable_java_executables.Length -eq 0) {
  $result="WARN"
} elseif ($error_encountered -eq $false -and $vulnerable_java_apps.Length -eq 0 -and $unreadable_java_apps.Length -gt 0) {
  $result="UNKNOWN"
} else {
  $result="ERROR"
}

if ($result -eq "FAIL") {
  Write-Log 'INFO' 'Result: FAIL'
  Write-Output @"

Result: FAIL
One or more vulnerable Java applications were found and Java 9+ was found on
the system. See output and JSON for paths. If the script was unable to scan any
applications, they will also be listed in the output and JSON. Note: if 
vulnerable applications are found and Java is found, but the Java version
cannot be determined, this will also result in FAIL.

"@    
} elseif ($result -eq "WARN") {
  Write-Log 'INFO' 'Result: WARN'
  Write-Output @"
Result: WARN
One or more vulnerable Java applications were found but Java 9+ was not found
on the system. See output and JSON for paths. If the script was unable to scan
any applications, they will also be listed in the output and JSON.

"@
} elseif ($result -eq "UNKNOWN") {
  Write-Log 'INFO' 'Result: UNKNOWN'
  Write-Output @"
Result: UNKNOWN
No vulnerable Java applications were detected, but the script was not able to 
detect all scanned applications. See output and JSON for paths.

"@
} elseif ($result -eq "PASS") {
  Write-Log 'INFO' 'Result: PASS'
  Write-Output @"
Result: PASS
All Java applications detected were scanned and no vulnerable applications were
found.

"@
} else {
  Write-Log 'INFO' 'Result: ERROR'
  Write-Output @"

Result: ERROR
The script encountered an error and was unable to complete. See error messages 
and log file for details.

"@
}

  $json_string = "{`n  `"result`":`"$result`",`n  `"hostname`":`"$hostname`",`n  `"scan_ts`":`"$scan_ts`",`n  `"scan_v`":`"0.3`",`n  `"search_root`":`"$search_root_escaped`",`n  `"vulnerable_application_paths`": ["
  
  if ($vulnerable_java_apps.Length -gt 0) {
    Write-Output "`nWARNING`nThe following vulnerable applications were found by this detection script:`n"
  }
  
  $i = 0
  foreach ($file in $vulnerable_java_apps) {
    $i += 1
    Write-Output "- $file"
    $file_escaped = Escape-JSON $file
    $json_string += "`"$file_escaped`""
    if ($i -lt $vulnerable_java_apps.length) {
      $json_string += ', '
    }
  }
  $json_string += "], `n  `"unknown_application_paths`": ["

  if ($unreadable_java_apps.Length -gt 0) {
    Write-Output "`nWARNING`nThe following applications were not readable by this detection script:`n"
  }
 
  $i = 0
  foreach ($file in $unreadable_java_apps) {
    $i += 1
    Write-Output "- $file"
    $file_escaped = Escape-JSON $file
    $json_string += "`"$file_escaped`""
    if ($i -lt $unreadable_java_apps.length) {
      $json_string += ", "
    }
  }
  $json_string += "], `n  `"java9plus_paths`": ["

  if ($vulnerable_java_executables.Length -gt 0) {
    Write-Output "`nWARNING`nThe following vulnerable java executables were found by this detection script:`n"
  }

  $i = 0
  foreach ($file in $vulnerable_java_executables) {
    $i += 1
    Write-Output "- $file"
    $file_escaped = Escape-JSON $file
    $json_string += "`"$file_escaped`""
    if ($i -lt $vulnerable_java_executables.length) {
      $json_string += ", "
    }
  }
  $json_string += "], `n  `"unknown_java_paths`": ["

  if ($unreadable_java_executables.Length -gt 0) {
    Write-Output "`nWARNING`nThe following java executables were not readable by this detection script:`n"
  }

  $i = 0
  foreach ($file in $unreadable_java_executables) {
    $i += 1
    Write-Output "- $file"
    $file_escaped = Escape-JSON $file
    $json_string += "`"$file_escaped`""
    if ($i -lt $unreadable_java_executables.length) {
      $json_string += ", "
    }
  }
  $json_string += "]`n}"

  $json_string | Out-File "$output_filepath"

  Write-Output ""
  Write-Output "For remediation steps, contact the vendor of each affected application."
  exit 1
