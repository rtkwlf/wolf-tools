# Arctic Wolf Spring4Shell Deep Scan

The Arctic Wolf Spring4Shell Deep Scan is designed to detect Java application 
packages subject to 
[CVE-2022-22965](https://tanzu.vmware.com/security/cve-2022-22965).

## Legal

Copyright 2022, Arctic Wolf Networks, Inc.

Arctic Wolf Networks, Inc. licenses this file to you under the Apache License,
Version 2.0 (the "License").  You may not use this file except in compliance
with the License.  You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.   


## Background

Java applications that contain a vulnerable version of the Spring Framework
and that are running on Java version 9 or greater may be subject to 
CVE-2022-22965.

This script searches the system for:

- Vulnerable Java Applications: Java applications that contain a version of the 
  Spring Framework that has not been patched (5.3.0 - 5.3.17, or < 5.2.20) to 
  remediate this vulnerability. The script explores Java packaging formats (jar,
  war, ear) to detect Spring inside of packages or packages within packages
  (nested packages).
- Java 9+: instances of Java (JRE or JDK) version 9 or greater. 

Systems containing vulnerable Java applications and Java 9+ may not be
vulnerable. This script does not attempt to determine whether the vulnerable
application is currently running, whether it is remotely-accessible or whether
it runs on Java 9+.

For remediation steps, contact the vendor of each vulnerable Java application.


## Scan Results

Each scan will have one of the following results:

- PASS: all Java applications detected were scanned and no vulnerable 
  applications were found.
- FAIL: one or more vulnerable Java applications were found and Java 9+ was
  found on the system. See output and JSON for paths. If the script was unable
  to scan any applications, they will also be listed in the output and JSON.
  Note: if vulnerable applications are found and Java is found, but the Java
  version cannot be determined, this will also result in FAIL.
- WARN: one or more vulnerable Java applications were found but Java 9+ was
  not found on the system. See output and JSON for paths. If the script was 
  unable to scan any applications, they will also be listed in the output and 
  JSON.
- UNKNOWN: no vulnerable Java applications were detected, but the script was
  not able to detect all scanned applications. See output and JSON for paths.
- ERROR: the script encountered an error and was unable to complete. See output
  for details.


## If You Find Vulnerable Applications

We recommend the following steps:

- Confirm the vulnerable application does not run on Java 9+
- Contact the vendor or application owner of each affected application for
  remediation steps


## Usage Instructions

Download the latest version here: [spring4shell_deep_scan_0.1.zip](https://github.com/rtkwlf/wolf-tools/raw/main/spring4shell/releases/spring4shell_deep_scan_0.1.zip).


### Windows

#### Important Notes

- This script requires .NET 4.5+
- This script should be run in a privileged context (i.e. as administrator)
- This script may use up to a single CPU and run for 1-20 minutes depending 
  on the size of the disk being search and the volume of files. Please test
  to assess resource impact and consider setting process priority if needed.

To run, open Command (cmd.exe) as administrator:

```
> powershell -ExecutionPolicy ByPass -f spring4shell_deep_scan.ps1
```

By default, all fixed drives will be searched. Specify a search_root as follows:

```
> powershell -ExecutionPolicy ByPass -f spring4shell_deep_scan.ps1 -search_root C:\START_HERE
```

Results will be written to a file in the current working directory as follows:

```
spring4shell_deep_scan.output.<hostname>.<timestamp>.json
```

To specify a file name for the output file, provide as a paramater as follows:

```
> powershell -ExecutionPolicy ByPass -f spring4shell_deep_scan.ps1 -output_filepath FILENAME_HERE.json
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
$ sudo sh spring4shell_deep_scan.sh
```

By default, all fixed drives will be searched. Specify a search_root as follows:

```
$ sudo sh spring4shell_deep_scan.sh /START_HERE
```

Results will be written to a file in the current working directory as follows:

```
spring4shell_deep_scan.output.<hostname>.<timestamp>.json
```

To specify a file name for the output file, provide as a paramater as follows:

```
$ sudo sh spring4shell_deep_scan.sh /START_HERE FILENAME_HERE.json
```
     
This can take several minutes. Ctrl-c to abort.


### JSON Output Examples

#### PASS

JSON output for scans that PASS will have @result="PASS" and no vulnerable
or unknown application path entries as follows:

```
{
  "result": "PASS",
  "hostname":"DESKTOP-US1234", 
  "scan_ts":"2021-12-16T18:14:09.7897291-06:00", 
  "scan_v":"0.1", 
  "search_root":"C:\\",
  "vulnerable_application_paths": [],
  "unknown_application_paths": [],
  "java9plus_paths": [],
  "unknown_java_paths": []
}
```

#### FAIL

JSON output for scans that FAIL will have @result="FAIL", path entries for
at least one vulnerable Java application, and path entries for at least one
Java 9+ or unknown Java version found on the system as follows:

```
{
  "result": "FAIL",
  "hostname":"DESKTOP-US1234", 
  "scan_ts":"2021-12-16T18:14:09.7897291-06:00", 
  "scan_v":"0.1", 
  "search_root":"C:\\",
  "vulnerable_application_paths": [ "C:\\Users\\user1234\\Downloads\\app.jar", "C:\\Users\\user1234\\Downloads\\app2.jar" ],
  "unknown_application_paths": [],
  "java9plus_paths": [ "C:\\Users\\user1234\\Downloads\\JRE10\java.exe" ],
  "unknown_java_paths": []
}
```

#### WARN

JSON output for scans that WARN will have @result="WARN" and path entries for
each vulnerable or unknown Java application or Java executable found on the 
system as follows:

```
{
  "result": "WARN",
  "hostname":"DESKTOP-US1234", 
  "scan_ts":"2021-12-16T18:14:09.7897291-06:00", 
  "scan_v":"0.1", 
  "search_root":"C:\\",
  "vulnerable_application_paths": [ "C:\\Users\\user1234\\Downloads\\app.jar", "C:\\Users\\user1234\\Downloads\\app2.jar" ],
  "unknown_application_paths": [],
  "java9plus_paths": [],
  "unknown_java_paths": []
}
```

#### UNKNOWN

JSON output for scans that UNKNOWN will have @result="UNKNOWN", no path 
entries for vulnerable applications, and at least one unknown application
path entryas follows:

```
{
  "result": "WARN",
  "hostname":"DESKTOP-US1234", 
  "scan_ts":"2021-12-16T18:14:09.7897291-06:00", 
  "scan_v":"0.1", 
  "search_root":"C:\\",
  "vulnerable_application_paths": [],
  "unknown_application_paths": [ "C:\\Users\\user1234\\Downloads\\app.jar" ],
  "java9plus_paths": [],
  "unknown_java_paths": []
}
```


#### FAIL or WARN with UNKNOWN

JSON output for scans that FAIL or WARN will have @result="FAIL" or
@result="WARN", path entries for at least one vulnerable Java application, path
entries for at least one unknown application, and entries for each vulnerable 
or unknown Java application or Java executable found on the system as follows:

```
{
  "result": "FAIL",
  "hostname":"DESKTOP-US1234", 
  "scan_ts":"2021-12-16T18:14:09.7897291-06:00", 
  "scan_v":"0.1", 
  "search_root":"C:\\",
  "vulnerable_application_paths": [ "C:\\Users\\user1234\\Downloads\\app.jar", "C:\\Users\\user1234\\Downloads\\app2.jar" ],
  "unknown_application_paths": [ "C:\\Users\\user1234\\Downloads\\app3.jar" ],
  "java9plus_paths": [ "C:\\Users\\user1234\\Downloads\\JRE10\java.exe" ],
  "unknown_java_paths": []
}
```

## Changelog

Version 0.1 released April 2, 2022 includes the following enhancements and resolutions:

- First release
