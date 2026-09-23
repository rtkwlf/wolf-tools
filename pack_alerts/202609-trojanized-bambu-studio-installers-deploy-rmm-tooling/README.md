# 2026-09-23: Trojanized Bambu Studio Installers Deploy Python-Based Loader and Remote Access Tooling

## ANALYSTS
- Steven Campbell, Stefan Hostetler, Kyle Siddall

## KEY FINDINGS
- Arctic Wolf identified a malware distribution campaign that used websites impersonating Bambu Lab—a developer of desktop 3D printers and Bambu Studio, a slicer application used to prepare 3D models for printing—to deliver Remote Monitoring and Management (RMM) tools, such as NetSupport Manager and MeshCentral MeshAgent.
- The malicious websites, which impersonated the Bambu Lab website, provide download links for trojanized Bambu Studio MSI installers hosted on Dropbox.
- Arctic Wolf observed installer variants using multiple publisher and product identities in installer metadata, using names such as `VaultAxis Software Corp.`, `Auralink Systems Inc.`, and `Harborbyte Systems Inc.`.
- Despite naming differences between variants, similar execution patterns are observed between them: a malicious MSI installer, a bundled Python runtime, a Python-based loader with outbound HTTPS activity, and deployment of RMM payloads.

## BACKGROUND
Bambu Lab develops desktop 3D printers and Bambu Studio, a legitimate slicer application used to prepare 3D models for printing. NetSupport Manager and MeshCentral MeshAgent are legitimate remote administration tools that threat actors abuse to maintain persistent remote access on compromised systems, leveraging their legitimate signatures and expected network communication patterns to reduce the likelihood of detection.

## TECHNICAL DETAILS

- Users visit a site impersonating Bambu Lab, including `studio-bambulab[.]com`, which points users towards a trojanized Bambu Studio installer, such as `Bambu_Studio_win-v02.08.02.60.msi`.
- The MSI package itself is hosted on Dropbox, separate from the rest of the lure site.
- When a victim executes the MSI, supporting files are saved to a variant-specific application directory and the loader script is launched through a bundled Python runtime.
- Loader script names and installation directories vary by publisher identity (e.g., `vaultaxis_secure_app.py` in `VaultAxis Software Corp\VaultAxis Secure\` for the VaultAxis variant; `auralink_studio_app.py` in `Auralink Systems\Auralink Studio\` for the Auralink Systems Inc. variant).
- The Python loader deploys a renamed copy of the legitimate Bambu Studio installer (`77706002c81d7177df11f426dbdd7348f34cb371f78a478d1ded402d67652632`), observed as `VaultAxisSync.exe` or `AuralinkService.exe` depending on the variant, which silently installs Bambu Studio v2.8.1 for Windows.
- During execution, `pythonw.exe` established connections to multiple remote destinations.

## DEFENSIVE CONSIDERATIONS

### Process Monitoring
- Monitor for `msiexec.exe` directly or indirectly launching command interpreters or scripting runtimes, including `cmd.exe`, `powershell.exe`, `python.exe`, and `pythonw.exe`. Prioritize activity in which the installer package, working directory, script, or runtime resides in a user-writable or non-standard location such as `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, or an unexpected `%PROGRAMDATA%` subdirectory.
- Investigate process chains resembling:

  ```
  msiexec.exe
  └── cmd.exe
      └── pythonw.exe
          └── Python script
  ```

- Pay particular attention to command shells using `start /b` to launch a windowless Python runtime:

  ```
  cmd.exe /c start "" /b "<path>\pythonw.exe" "<path>\<script>.py"
  ```

### Behavioral Hunting
- Hunt for unapproved RMM tool execution, including components renamed to resemble security or business software. Do not rely solely on the current executable name. Review original filename, product metadata, signer information, adjacent configuration files, installation path, and network activity.
- Monitor for the following anomalous scenarios:
  - Execution from user-profile or other non-standard directories
  - References to unexpected `.ini` configuration files
  - Recently created or renamed binaries
  - Execution through a Startup shortcut
  - Systems without an approved RMM tool deployment

### Network Detection
- Review DNS, proxy, firewall, and endpoint network telemetry for communication with the listed infrastructure during the reported activity period. Where organizational policy permits, block confirmed malicious infrastructure and alert on attempted connections.

### Persistence Review
- Review recently created or modified `.lnk` files in the following Startup locations:
  - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  - `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp`
- Review suspicious `.lnk` files pointing to non-standard executables.
  - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SecurityHeal.lnk`

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# SHA256
2c67d1b843b12c83e83835ef73a5979fd4137e723ef3f6d39172a349535d573c # Bambu_Studio_win-v02.08.02.60.msi – VaultAxis Software Corp. Variant
64a6076e7e7823c27ae2d0174052a8a1efb48389cb7e93dc645e9440388f2e3a # Bambu_Studio_win-v02.08.02.63.msi – Harborbyte Systems Inc. Variant
e52d67107a09b8c22e3c12172e149af2ea2b9ebf531796a57246db272f8bd7f1 # Bambu_Studio_win-v02.08.02.64.msi – Auralink Systems Inc. Variant
d2e6a43584ca6e8058ac722b53a745c334c3a338c8554a281c1726b1225f3ef9 # Bambu_Studio_win-v02.08.02.61.msi – Northbridge Software Inc. Variant
275e5b085534f64313b50cbdcb08ecd59c57d21c96bb937f140ee92a3d27f792 # SecurityHeal.exe (renamed NetSupport Manager)

# DOMAIN NAMES
studio-bambulab[.]com # Impersonation domain
studio-bambulabs[.]com # Impersonation domain
core-bambulab[.]com # Impersonation domain
storebambulab[.]com # Impersonation domain
360organicottage[.]com # HTTPS connection observed during timeframe
sctubajie[.]com # HTTPS connection observed during timeframe
api[.]jlonghardware[.]com # HTTPS connection observed
s311030[.]love-is[.]nexus # HTTPS connection observed
ww[.]messiturf10[.]fr # HTTPS connection observed
cdn[.]adescareonline[.]com # HTTPS connection observed
cldesktop[.]b-cdn[.]net # CNAME record for cdn[.]adescareonline[.]com

# IP ADDRESSES
176[.]53[.]159[.]149 # NetSupport C2
109[.]120[.]137[.]193 # Associated with s311030[.]love-is[.]nexus hostname; communication via port 3306
45[.]61[.]161[.]229 # IP reached out to by pythonw.exe during MSI installation; A Record of ww[.]messiturf10[.]fr
138[.]199[.]40[.]58 # A record for cdn[.]adescareonline[.]com (Datacamp Limited)
45[.]83[.]181[.]13 # A record for api[.]jlonghardware[.]com (BlueVPS OU)

# FILE NAMES
Bambu_Studio_win-v02.08.02.60.msi
Bambu_Studio_win-v02.08.02.61.msi
Bambu_Studio_win-v02.08.02.63.msi
Bambu_Studio_win-v02.08.02.64.msi
SecurityHeal.exe # Renamed NetSupport Manager
PCICL32.DLL
SecurityHeal.lnk
msh.lnk # File created by pythonw.exe process spawned during installation

# FILE PATHS
C:\Users\<user>\AppData\Local\Netsupport Manager\SecurityHeal.exe
C:\Users\<user>\AppData\Local\VaultAxis Software Corp\VaultAxis Secure\vaultaxis_secure_app.py
C:\Users\<user>\AppData\Local\VaultAxis Software Corp\VaultAxis Secure\host_layer\pythonw.exe
C:\Users\<user>\AppData\Local\Programs\Bambu\VaultAxisSync.exe
C:\ProgramData\Losslesse\pythonw.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SecurityHeal.lnk

# COMMAND LINES
SecurityHeal.exe /csolaf.ini
cmd.exe /c start "" /b "<path>\pythonw.exe" "<path>\vaultaxis_secure_app.py"
```
