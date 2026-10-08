# 2026-10-08: Dropping Elephant Targets Defense, Government, and Naval Sectors in Active Multi-Country APAC Espionage Campaign

## ANALYSTS
- Arctic Wolf Labs, Adversary Research

## KEY TAKEAWAYS
- Dropping Elephant (also tracked as Patchwork, APT-C-09) is an India-nexus adversary active since at least mid-2016, operating in line with Indian state intelligence collection priorities.
- The group continues conducting cyber-espionage activity targeting government entities and strategically significant industries across the Asia-Pacific region, consistent with activity documented in prior Arctic Wolf Labs reporting.
- The group continues to use spear-phishing campaigns with malicious LNK attachments to deliver PowerShell-based malware, DLL sideloading payloads, and in-memory RAT.
- Targeting has been observed across Pakistan, Sri Lanka, China, and South Korea, with a focus on government, defense, naval, aerospace/UAV, academic, and other strategically significant sectors.
- Arctic Wolf Labs attributes this activity with medium-to-high confidence to Dropping Elephant, based on the remote access trojan (RAT) used, Shortcut file metadata, PowerShell obfuscation and DLL sideloading tradecraft consistent with prior campaigns and delivery infrastructure patterns aligned with known Dropping Elephant operational behavior.

## TECHNICAL DETAILS
- LNK files invoke PowerShell via `cmd.exe` wildcard resolution (`cmd /c for /F %i in ('where p*s*ll.?x?') do %i`), direct invocation, or wrapped through `conhost[.]exe` — consistently avoiding the literal string `powershell.exe` in command-line telemetry. Cmdlet names and arguments are fragmented throughout with empty quote pairs (`wg''et`, `iw''r`, `sc''hta''sks`, `r''e''n`, `S''C''H''T''A''S''K''S''`). Payloads are downloaded either with garbled extensions (`.ezxzez`→`.exe`, `.dylyly`→`.dll`, `.dzlzlz`→`.dll`, `.cypyly`→`.cpl`) stripped via `Get-ChildItem | Rename-Item -NewName {$_.Name -replace 'char',''}`, or to short random filenames renamed directly to their final form. No unpacker is required on disk.
- Payloads are staged to `C:\Users\Public\` or `C:\Windows\Tasks\`. DLL sideloading is used throughout; observed loader pairs: `cef_demo.exe`/`cef_frame.dll` (Chromium Embedded Framework), `vlc.exe`/`libvlc.dll` (VLC Media Player), `msdtc32.exe`/`msdtctm.dll` (MS DTC), `java.exe`/`jli.dll` (JRE), `Fondue.exe`/`APPWIZ.cpl` (Windows Features installer), `dpapimig.exe`/`SAMLIB.dll`, `SystemSettings.exe`/`SystemSettings.dll`, and `Services.exe`.
- Scheduled tasks are created to execute every minute under names masquerading as legitimate system processes (`GoogleUpdateTaskMachineBA`, `MicrosoftEdgeUpdateTask`, `GoogleErrorReport`, `GoogleReport`, `GoogleUpdateTask`, `EdgeUpdate`, `WindowsErrorReport`). Persistence is established via `schtasks.exe` in most samples — invoked with character-level quote fragmentation (`S''C''H''T''A''S''K''S''`) or resolved via `Get-Command` wildcard (`g''cm sch*`). One sample uses `Register-Sche''duledTa''sk` exclusively with fully fragmented `New-ScheduledTask*` cmdlets, spawning no `schtasks.exe` process.
- The delivery IP (`223.165.5[.]38`) resolves to BrainStorm Network, Inc (ASN 136258, Pakistan). Active scanning shows IKE/UDP 500 on the host, indicating a VPN endpoint – consistent with the threat actor routing delivery traffic through in-country VPN infrastructure to blend with target-country network patterns.
- The RAT C2 (`techmomentum[.]org`) uses HTTP on port 2000; response payloads are AES-encrypted and base64-encoded before transmission.

## HUNTING GUIDANCE
- Scheduled tasks: Alert on scheduled tasks with a one-minute trigger interval where the executed binary path resolves to `C:\Users\Public\` or `C:\Windows\Tasks\`. Alert on `schtasks.exe` spawned by PowerShell or `cmd.exe` with `/create /Sc minute` arguments targeting either path. Also alert on `Register-ScheduledTask` called from PowerShell, where the action executable references `C:\Users\Public\` — this group uses PowerShell-only task registration in at least one sample to avoid spawning `schtasks.exe`.
- Filesystem: Alert on executable, DLL, or CPL files written to `C:\Users\Public\` or `C:\Windows\Tasks\` outside of known installer processes. Specific filenames of interest: `cef_demo.exe`, `cef_frame.dll`, `vlc.exe`, `libvlc.dll`, `msdtc32.exe`, `msdtctm.dll`, `java.exe`, `jli.dll`, `Fondue.exe`, `APPWIZ.cpl`, `dpapimig.exe`, `SAMLIB.dll`, `SystemSettings.exe`, `Services.exe`.
- Process: Alert on `cmd.exe` spawning PowerShell where the command line contains `where p*s*ll` or a `for /F` loop resolving a binary path. Also alert on PowerShell `Rename-Item` where the source filename contains repeated-character patterns (`ezxzez`, `dylyly`, `dzlzlz`, `cypyly`).
- Network: Block or alert on outbound connections to `techmomentum[.]org` on port 2000. Inspect proxy/firewall logs for the URI path `/SqX55Z32TtCh/oA3gW185qmtI.php`. Outbound traffic to `223.165.5[.]38` from non-browser processes should be treated as high-fidelity.

## ADDITIONAL RESOURCES
- [Dropping Elephant APT Group Targets Turkish Defense Industry — Arctic Wolf Labs](https://arcticwolf.com/resources/blog/dropping-elephant-apt-group-targets-turkish-defense-industry/)

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# DOMAINS (LNK delivery infrastructure)
zonawood[.]org
zong[.]elpaies[.]info
pakonline[.]org
navalinfo[.]org
ncciapk[.]org
webrobt[.]org

# DOMAIN (RAT C2)
techmomentum[.]org

# IP ADDRESS (LNK delivery infrastructure — BrainStorm Network, Inc / ASN 136258 / PK; IKE/UDP 500 present on host — consistent with VPN endpoint use for delivery routing)
223[.]165[.]5[.]38

# SHA256 (Malicious LNK files, 2026 first submissions only)
49b36ccf7d44f039aad0f69068362586485a1f5c0f22ffb217f075306514420d # Bank_Requisition.lnk (2026-09-17)
2d3f634deb8247eb2b7b0f0e6d3b62d2d955d42924b72a6b61701d0c7a3a0173 # P26SPF211985.lnk (2026-09-17)
ca5609a6ff44092131e5da8425b2d0c5152ac5e7adc42231aa4d2dc36d529559 # Suspention.lnk (2026-09-10)
d1ae51e18644263c9fdf618b285c978edb46507295faaf60062794011afb31b9 # ICASSE2026.lnk (2026-07-31)
abe4393a39b6a2020ebf3a7ebafc18fffc597f0094b83ebbbccd4ab3b9b9a5bf # Newsletter_PWD.pdf.lnk (2026-07-09)
dbcf827b33a29d4911b08e4f380e65b1495ff97d6893e4ce568c67cd1a8bbc7d # 84578.lnk (2026-05-20)
9b2637b8fefeedf8dca8a0ace491de05b6d937ea7463b48562cd1a0f25abb9f5 # FAKE_CAPTCHA.lnk (2026-04-23)
75749c315f39faf32ab6758f3c1cb0cc992150ab4a3e841a3afc5679bb639ab1 # SF026_211.lnk (2026-03-24)
24e16b13be82a21d4ebd38715deccaf55d34023507918825f40e1071c8da92a5 # DD_summary.pdf.lnk (2026-02-10)
660ad610b7ab9d090274cea9cc5f149c665d7343dad8c133ae559b2321a14244 # Application_Form.lnk (2026-01-16)

# SHA256 (RAT samples)
66d05029a7a74fde73749ed1a71f5df87b0c0815923a230f078632d48072fb3d # Configured build — C2: techmomentum[.]org
f188173571060d7a446cc4ac4984e042e6051d69f085f7945e9672f830c5acfb # Pre-config build — same compile run

# RAT NETWORK INDICATORS
C2 domain: techmomentum[.]org
C2 port: 2000
C2 URI path: /SqX55Z32TtCh/oA3gW185qmtI.php
```
