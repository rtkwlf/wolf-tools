# 2026-11-03: Edgecution Returns with Fake Microsoft Updates and Rotating Cloud Infrastructure

## ANALYSTS
- Arctic Wolf Labs, Adversary Research

## KEY FINDINGS
- In October 2026, Arctic Wolf Labs began tracking a new wave of Microsoft social engineering activity exhibiting similarities to the previously reported Edgecution campaign.
- In the October wave, following a lull in observed cases from August to September, new delivery artifacts and operational patterns were observed compared to the initial reporting. The campaign abuses a malicious Edge extension and Chrome Native Messaging to run a Python backdoor outside the browser sandbox.
- Threat actors rotated through Teams sender identities tied to distinct Microsoft 365 tenants, S3 buckets, CloudFront distributions, extension IDs, and payload names between deployments. The actor retained a stable execution chain from Task Scheduler to headless Edge, Chromium Native Messaging, portable Python, and command execution.
- The activity shares early chain tradecraft with PREY-0059, including external-tenant Teams impersonation of IT support, legitimate runtimes paired with scripts, and S3-hosted payloads disguised as legitimate software.
- While PREY-0059 used S3 buckets named after targeted victims and delivered a Java-based RAT alongside a Java runtime, the current activity used generic Microsoft-themed tenants and buckets, an Edge extension, and a Python backdoor paired with a Python runtime.

## TECHNICAL DETAILS
- Windows executable payloads and a legitimate AutoHotkey binary were downloaded via AWS S3 bucket URLs. Payload names were changed from earlier `patch<number>` and `set<number>` naming conventions to `kb<number>` filenames intended to resemble Microsoft Knowledge Base update packages. The corresponding use of the `ms-service-page-` prefix in S3 buckets reinforces this narrative.
- The file named `kb<number>.exe` is a renamed copy of the legitimate AutoHotkey v2 interpreter; malicious logic resides in the paired `kb<number>.ahk` script, which differs between victims.
- On execution, the AutoHotkey script repairs an archive with its header bytes removed, then extracts it. A portable Python runtime is then extracted along with `extension` and `native` directories, and the initial delivery artifacts are removed.
- The dropper loaded the legitimate Windows `taskschd.dll` component around the time `native_host.bat` was written.
- On several affected endpoints, Edge launched a new Python native-host process repeatedly, in some cases at approximately 30-second intervals.
- In some instances, AD discovery commands were later launched by `native_host.py` through child `cmd.exe` processes, with output staged to a `tmp.txt` file under `%LOCALAPPDATA%` and read back. Associated telemetry showed activity involving Kerberos, LDAP, SMB, and RPC services, including connections to domain controllers and certificate authority servers.

The recurring execution chain was:

```
svchost.exe -k netsvcs -p -s Schedule
  └── msedge.exe
      --headless=new
      --user-data-dir=<custom profile>
      --load-extension=<user-writable extension directory>
      --no-first-run
      --disable-sync
      └── cmd.exe /d /s /c "<path>\native_host.bat"
          chrome-extension://<extension-id>/
          --parent-window=0
          └── C:\ProgramData\python-<version>\python.exe -u
              "<path>\native_host.py"
              └── cmd.exe /c <operator command>
```

## HUNTING GUIDANCE
- Hunt for the Windows Task Scheduler service launching `msedge.exe` with `--headless`, `--load-extension`, and `--user-data-dir` in the same command line.
- Investigate unpacked Edge extensions loaded from user-writable locations, particularly directories containing `WorkspacesNavigation`, `TrustProtectExtension`, `native_host.bat`, or `native_host.py`.
- Hunt for `msedge.exe` launching `cmd.exe` with `native_host.bat`, `chrome-extension://`, and `--parent-window=0` in the command line.
- Look for Python executing from `C:\ProgramData\python-*` with the arguments `-u` and `native_host.py`.
- Prioritize events where `native_host.py` or its child command shell executes `net.exe`, `nltest.exe`, `nslookup.exe`, `systeminfo.exe`, or other discovery utilities.
- Correlate new external Teams chats with support- or engineering-themed Microsoft 365 identities, `QuickAssist.exe` execution, AutoHotkey execution, and subsequent S3 downloads.
- Hunt for paired `.ahk` and `.exe` downloads sharing the same `kb<number>` basename.
- Prioritize behavioral detection over individual extension IDs, S3 buckets, and CloudFront distributions.

## DEFENSIVE CONSIDERATIONS
- Restrict Microsoft Teams external access to a list of trusted domains. Block communication with accounts in unmanaged and trial Microsoft 365 tenants.
- Remove Quick Assist from endpoints where it is not required, or restrict it to approved users, and educate employees and help-desk staff that IT will not initiate contact over external Teams chats or ask users to run downloaded updates.
- Use application control (AppLocker or WDAC) to block execution of `AutoHotkey` interpreters and interpreters such as `python.exe` residing in user-writable paths such as `C:\ProgramData`, and apply Attack Surface Reduction rules where available.
- Manage Edge extensions with enterprise policy by setting `ExtensionInstallBlocklist` to `*` with an explicit allowlist, and disable user-level native messaging hosts with `NativeMessagingUserLevelHosts`.
- Alert on creation of scheduled tasks that launch `msedge.exe` with `--headless` or `--load-extension`. Tasks created through the Task Scheduler COM API do not produce `schtasks.exe` process events, so also monitor task registration events and the `TaskCache` registry keys.
- Do not rely on file-hash detection alone. The `.exe` is a legitimate AutoHotkey interpreter, and the `.ahk` script, S3 buckets, CloudFront distributions, and extension IDs change between victims.
- If implant execution is confirmed, isolate the endpoint and consider reimaging since the Python backdoor supports arbitrary command and code execution. Reset affected credentials, revoke sessions and tokens, and review downstream identity and domain activity.

## ADDITIONAL RESOURCES
- [https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution](https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution)
- [https://medium.com/@coormac/edgecution-teams-social-engineering-delivers-malicious-browser-extension-and-python-rat-794afa9f6c36](https://medium.com/@coormac/edgecution-teams-social-engineering-delivers-malicious-browser-extension-and-python-rat-794afa9f6c36)

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# FILE PATHS
C:\ProgramData\python-3.14.7\
%LOCALAPPDATA%\Microsoft\Edge\User Data\WorkspacesNavigation\
%LOCALAPPDATA%\Microsoft\Edge\User Data\WorkspacesNavigation\TrustProtectExtension\
%LOCALAPPDATA%\Microsoft\Edge\User Data\WorkspacesNavigation\TrustProtectExtension\a.zip
%LOCALAPPDATA%\Microsoft\Edge\User Data\WorkspacesNavigation\TrustProtectExtension\native\native_host.bat
%LOCALAPPDATA%\Microsoft\Edge\User Data\WorkspacesNavigation\TrustProtectExtension\native\native_host.py

# FILENAMES
native_host.bat
native_host.py

# S3 BUCKET PATTERN
ms-service-page-<five digits>-<five digits>-<five digits>[.]s3[.]amazonaws[.]com
outlook-service-page-<five digits>-<five digits>-<five digits>[.]s3[.]amazonaws[.]com

# C2 FQDN PATTERN
wss[:]//<fourteen alphanumeric characters>[.]cloudfront[.]net/ws

# PAYLOAD NAMING CONVENTIONS
kb<number>.exe # Legitimate AutoHotkey binary a2a54b8abc476d7671d4de0771bb54bf5f2373d79ff6871d0ba6a62c3b88ae00
kb<number>.ahk
kb<number>.a

# CHROMIUM EXTENSION NAME
TrustProtectExtension

# TEAMS SENDERS
support[@]techsupportsecurityllc[.]onmicrosoft[.]com
HelpDesk[@]ITSignin[.]onmicrosoft[.]com
IT[@]RootAdminCore[.]onmicrosoft[.]com
Support_IT[@]ITAdminWork[.]onmicrosoft[.]com
Corp_Engineer[@]SofwtareEngineringIN[.]onmicrosoft[.]com
Engineer_Corp[@]SystemCoreIN[.]onmicrosoft[.]com
Corp_Engineer[@]CodeVision853[.]onmicrosoft[.]com
Corp_Engineer[@]DomainDigital034[.]onmicrosoft[.]com
Engineer_Local[@]ComputerHub788[.]onmicrosoft[.]com
Engineer_Local[@]TechnicalEngineerInternal00[.]onmicrosoft[.]com

# AD RECON COMMANDS
net group "Domain Admins" /dom
nltest /dclist:<domain>
nltest /domain_trusts
nslookup -type=srv _ldap._tcp.<domain>
ipconfig /all
systeminfo
net user
```
