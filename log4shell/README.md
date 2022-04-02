# Arctic Wolf Log4Shell Deep Scan

The Arctic Wolf Log4Shell Deep Scan is designed to detect Java application packages
subject to [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and 
[CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046).

## Legal

Copyright 2021, Arctic Wolf Networks, Inc.

Arctic Wolf Networks, Inc. licenses this file to you under the Apache License,
Version 2.0 (the "License").  You may not use this file except in compliance
with the License.  You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.   


## Background

This script searches the system for Java applications that contain the Log4J
class JndiLookup.class which is the source of the Log4Shell vulnerabilities. If
this class is found within an application, the script looks for updates to Log4J 
that indicate the application has been updated to use Log4J 2.16+ or Log4J 
2.12.2+. If the application contains JndiLookup.class but does not appear
to have been updated, the application is vulnerable.

For additional details, see:

- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://nvd.nist.gov/vuln/detail/CVE-2021-45046
- https://logging.apache.org/log4j/2.x/security.html

For remediation steps, contact the vendor of each affected application.


## Scan Results

Each scan will have one of the following results:

- PASS: all Java applications detected were scanned and no vulnerable 
  applications were found.
- FAIL: one or more vulnerable Java applications were found. See output and 
  JSON for paths. If the script was unable to scan any applications, they 
  will also be listed in the output and JSON.
- UNKNOWN: no vulnerable Java applications were detected, but the script was
  not able to detect all scanned applications. See output and JSON for paths.
- ERROR: the script encountered an error and was unable to complete. See output
  for details.


## If You Find Vulnerable Applications

For remediation steps, contact the vendor of each affected application.

## Usage Instructions

Download the latest version here: [log4shell_deep_scan_0.3.zip](https://github.com/rtkwlf/wolf-tools/raw/main/log4shell/releases/log4shell_deep_scan_0.3.zip).

### Windows

#### Important Notes

- This script requires .NET 4.5+
- This script should be run in a privileged context (i.e. as administrator)
- This script may use up to a single CPU and run for 1-20 minutes depending 
  on the size of the disk being search and the volume of files. Please test
  to assess resource impact and consider setting process priority if needed.

To run, open Command (cmd.exe) as administrator:

```
> powershell -ExecutionPolicy ByPass -f log4shell_deep_scan.ps1
```

By default, all fixed drives will be searched. Specify a search_root as follows:

```
> powershell -ExecutionPolicy ByPass -f log4shell_deep_scan.ps1 -search_root C:\START_HERE
```

Results will be written to a file in the current working directory as follows:

```
log4shell_deep_scan.output.<hostname>.<timestamp>.json
```

To specify a file name for the output file, provide as a paramater as follows:

```
> powershell -ExecutionPolicy ByPass -f log4shell_deep_scan.ps1 -output_filepath FILENAME_HERE.json
```

This can take several minutes. Ctrl-c to abort.


### Linux/macOS

#### Important Notes

- This script should be run in a privileged context (i.e. as root or using 
  sudo) so it can access the entire system.
- This script may use up to a single CPU and run for 1-20 minutes depending 
  on the size of the disk being search and the volume of files. Please test
  to assess resource impact and consider using `nice` if needed.

To run, open command prompt:

```
$ sudo sh log4shell_deep_scan.sh
```

By default, all fixed drives will be searched. Specify a search_root as follows:

```
$ sudo sh log4shell_deep_scan.sh /START_HERE
```

Results will be written to a file in the current working directory as follows:

```
log4shell_deep_scan.output.<hostname>.<timestamp>.json
```

To specify a file name for the output file, provide as a paramater as follows:

```
$ sudo sh log4shell_deep_scan.sh /START_HERE FILENAME_HERE.json
```
     
This can take several minutes. Ctrl-c to abort.


### JSON Output Examples

#### PASS

JSON output for scans that PASS will have 1 entry as follows:

```
[
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:24:46.8919939-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"PASS", "vulnerable_jar":false } 
]
```

#### FAIL

JSON output for scans that FAIL will have 1 entry for each vulnerable Java
application found on the system as follows:

```
[
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:14:09.7897291-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"FAIL", "vulnerable_jar":"C:\\Users\\user1234\\Downloads\\apache-log4j-2.12.1-bin\\log4j-core-2.12.1.jar" },
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:14:09.7897291-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"FAIL", "vulnerable_jar":"C:\\Users\\user1234\\Downloads\\apache-log4j-2.12.1-bin.jar!log4j-core-2.12.1.jar" },
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:14:09.7897291-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"FAIL", "vulnerable_jar":"C:\\Users\\user1234\\Downloads\\log4j-core-2.12.1.jar" }
]
```

#### FAIL with UNKNOWN

JSON output for scans that FAIL and have unscanned jars will have 1 entry for
each vulnerable or unscanned Java application found on the system as follows:

```
[
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:14:09.7897291-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"FAIL", "vulnerable_jar":"C:\\Users\\user1234\\Downloads\\apache-log4j-2.12.1-bin\\log4j-core-2.12.1.jar" },
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:14:09.7897291-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"FAIL", "vulnerable_jar":"C:\\Users\\user1234\\Downloads\\apache-log4j-2.12.1-bin.jar!log4j-core-2.12.1.jar" },
  { "hostname":"DESKTOP-US1234", "scan_ts":"2021-12-16T18:14:09.7897291-06:00", "scan_v":"0.3", "search_root":"C:\\", "result":"UNKNOWN", "unscanned_jar":"C:\\Users\\user1234\\Downloads\\log4j-3234-2.12.1.jar" }
]
```

## Changelog

Version 0.3 released December 17, 2021 includes the following enhancements and resolutions:

- First open-source release
- Updated license, documentation, and naming

Version 0.2 released December 17, 2021 includes the following enhancements and resolutions:

- Checks for CVE-2021-45046 in addition to CVE-2021-44228
- Checks for Log4J 2.12 branch patch (2.12.2+) in addition to current release patch (2.16+)
- Added support for .war and .ear Java packaging formats in addition to .jar
- Adds UNKNOWN result to capture unscannable Java application packages
- Checks nested packages (jar/war/ear within jar/war/ear)
- Creates a log file 
- Adds hostname to default output filename
- Additional minor feature enhancements and bug fixes
