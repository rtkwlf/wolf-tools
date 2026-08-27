# 2026-08-26: Malicious GitHub repositories use redirects to fingerprint devices and deliver tailored payloads: BoryptGrab infostealer ZIPs on Windows and malicious Android APKs linked to a newly identified C2 panel

## ANALYSTS
- Steven Campbell, Alyssa Newbury, and Akshay Suthar

## KEY TAKEAWAYS
- This activity continues the BoryptGrab-affiliated SEO poisoning campaign reported by Arctic Wolf Labs in July 2026, with subsequent research identifying a new command-and-control panel, "Drama" associated with the campaign. 
- Threat actors publish public GitHub repositories advertising free, ostensibly legitimate software tools and use SEO keywords in README files to increase their visibility in search results. 
- Repository download links funnel victims through multiple intermediary redirects to a verification page that fingerprints the device and determines which platform-specific payload to serve. The final download link is presented only after the redirect and verification process succeeds. 
- Windows users receive a ZIP archive containing a BoryptGrab-lineage infostealer, with the executable named after the software tool the victim searched for. Android users are served a malicious APK that installs automatically after download. 
- Server-side polymorphism produces functionally equivalent but structurally distinct payloads at delivery, resulting in different cryptographic hashes and static characteristics that reduce the effectiveness of hash-based blocking and signature-based detection. 

## TECHNICAL DETAILS
- Redirect chain: `GitHub lure > GitHub repository > Redirect domain 1 > Redirect domain 2 > Payload domain`.
- Observed payload domains differed across fingerprinted Windows hosts; however, all APK payloads were dropped from the same payload domain: (`kansamyope[.]com`). 
- Victim fingerprinting occurs before payload delivery.  
- The redirect script expects a user code in the URL.
- If one is not present, the victim is redirected to a benign webpage and no payload is delivered. 
- Both a Windows and an Android payload variant have been observed. 
- Windows variant matches BoryptGrab infostealer code lineage. 
- Stolen information is sent via POST request to a hardcoded C2 endpoint: `hxxp://2.26.126[.]50:80/upload`. 
- Exfiltrated ZIP file naming convention: `<IP country code>_<victim IP address>_YYYY-MM-DD HH_MM_SS_<unique victim GUID>.zip`
- The malicious APK file communicates with `172.43.172[.]187`, which hosts a C2 panel (“drama”). 

ADDITIONAL RESOURCES: [Malicious GitHub Campaign: Fake “Arctic Wolf” and 290+ Brand-Impersonation Repositories Deliver BoryptGrab-Lineage Infostealer](https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/) 

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive. 

```
# REPOS (Malicious GitHub Repositories)
github[.]com/DoNotSpy11
github[.]com/Crosshair-X-Aim-Tool
github[.]com/VitalPBX-Phone-System
github[.]com/Tuta-Encrypted-Email
github[.]com/SolveSpace-Parametric-CAD
github[.]com/Avaya-IP-Office-System
github[.]com/Roland-M-5000-OHRCA-Console

# DOMAINS (Observed payload domains)
sertascudi[.]com 
halalsabal[.]com 
quatastroy[.]com 
albinofennel[.]com 
targetroyena[.]com 
kansamyope[.]com – APK payload domain 

# DOMAINS (Intermediary redirects before payload delivery)
greysilkvoid[.]com 
quietstormhash[.]com 
usarawhalm[.]com 
walkeddarkflower[.]com 
coldrainfiber[.]com 
neosunvirex[.]com 
dreamfastcrow[.]com 
lostmildflame[.]com 
macperformancetools[.]com 
istatlmenus[.]com

# EMAIL ADDRESSES (Registrant email addresses linked to domain clusters observed)
isaiahwarren199209[@]flixtrend[.]net 
c.garcia90[@]marshier[.]com 
andrew.powell05[@]quickblox[.]net 

# URLS
hxxps://joshualandrynrsy[.]github[.]io/.github/DoNotSpy11 
hxxps://massimolongqdoj[.]github[.]io/.github/DoNotSpy11 
hxxps://vickiebrooksvic[.]github.io/.github/crosshair-x-aim-tool 
hxxps://braylenfryufwa[.]github.io/.github/hibituninstaller 
hxxps://baldassar62[.]github.io/.github/ShareX-Windows 
hxxps://kristianlacerkkedrf[.]github.io/.github/VitalPBX-Phone-System 

# SHA256
9cdc67c4f5442f4c26e04b594361b021779017fa13eadbe5329b09d9a07c6efc
d04c05431bea6ac7299fd6ebb28f04234f483fb8ebe3d0e640b301b4c5a75770 – DoNotSpy11-6.99.3.apk

# MAIN C2 SERVER (for Windows Infostealer)
2.26.126[.]50

# C2 SERVERS (Associated with Drama Panel)
179.43.146[.]126
179.43.146[.]125
179.43.146[.]124
179.43.146[.]122
179.43.172[.]187

# DOMAINS (Drama Panel associated domains)
rat[.]vg
drama[.]vg

# TELEGRAM
Username: @drama_ok

# PAYLOAD FILENAMES OBSERVED
joshualandrynrsy-8.49.5.zip
joshualandrynrsy-7.96.2.zip
VitalPBX-Phone-System-6.5.4.zip
VitalPBX-Phone-System-6.5.4.exe
crosshair-x-aim-tool-5.86.1.zip
crosshair-x-aim-tool-5.86.1.exe
DoNotSpy11-6.99.3.apk
```
