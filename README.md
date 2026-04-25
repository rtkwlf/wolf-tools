# wolf-tools

Open source tools and scripts by Arctic Wolf:

## Vulnerability Scanners

- [Arctic Wolf Log4Shell Deep Scan](log4shell/README.md): detects Java application packages
subject to [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and 
[CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046)
- [Arctic Wolf Spring4Shell Deep Scan](spring4shell/README.md): detects Java application packages
subject to [CVE-2022-22965](https://tanzu.vmware.com/security/cve-2022-22965)

## Threat Intelligence

Detection rules, IOCs, and artifacts published by Arctic Wolf Labs.

- [CVE-2023-22527 Leading to C3RB3R Ransomware](threat-intelligence/cve-2023-22527-leading-to-c3rb3r/README.md): YARA rules to detect activity seen during exploitation of Confluence Server via CVE-2023-22527
- [Lorenz Ransomware: Chiseling In](threat-intelligence/lorenz-ransomware-chiseling-in/README.md): YARA rules, Suricata rules, and IOCs associated with the Lorenz ransomware group
- [Lorenz Ransomware: Getting Dumped](threat-intelligence/lorenz-ransomware-getting-dumped/README.md): IOCs, artifacts, Sigma rules, and YARA rules related to unexpected use of Magnet RAM Capture by Lorenz ransomware actors
- [WDAC Policy for Iranian App Abuse (2025)](threat-intelligence/wdac-blocking-iranian-app-abuse-2025/README.md): Windows Defender Application Control policy to block dual-use application abuse by Iranian threat groups
