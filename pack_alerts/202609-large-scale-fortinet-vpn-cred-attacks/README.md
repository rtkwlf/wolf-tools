# 2026-09-02: Large-Scale Credential Attacks Target Fortinet VPNs Using Organization-Specific Identities

## ANALYSTS
- Kyle Siddall

## KEY FINDINGS
- Between August 26 and August 28, 2026, Arctic Wolf observed a large-scale credential attack campaign against internet-facing Fortinet VPN services that targeted hundreds of organizations and generated tens of millions of authentication failures. One reviewed environment recorded more than 58 million failed attempts.
- The actor used organization-specific usernames, corporate email addresses, affiliate accounts, and common administrative identities, indicating access to previously collected or enumerated identity information.
- Arctic Wolf identified a successful Fortinet VPN authentication from campaign infrastructure that was followed by confirmed malicious activity in the affected environment.

## BACKGROUND
The campaign used infrastructure associated with Omegatech LTD (AS202412) and M247 Europe SRL. Its scale and organization-specific targeting distinguish it from generic username spraying.

## TECHNICAL DETAILS AND ATTACK FLOW
1. The actor generated high-volume authentication activity in two sustained waves across multiple US customer environments from August 26 through August 28, 2026.
2. The attempted usernames included employee names, corporate email addresses, affiliate identities, and common administrative accounts associated with the targeted organizations.
3. Arctic Wolf confirmed a successful Fortinet VPN authentication from `158[.]94[.]211[.]14` followed by malicious activity in the affected environment.
4. Successful VPN authentications from the identified infrastructure should be treated as potential intrusion footholds and investigated immediately.

## DEFENSIVE CONSIDERATIONS
- Investigate successful Fortinet VPN authentications from the listed IP addresses and ASNs; contain active sessions, review affected endpoints, and remediate compromised credentials.
- Review authentication logs from 2026-08-26 through 2026-08-28 for high-volume failures and lower-volume successes from the same infrastructure.
- Hunt for successful logins using organization-specific usernames that were preceded by repeated failures from the same source infrastructure.
- Correlate suspicious Fortinet VPN authentications with follow-on activity such as new internal connections, privilege use, account changes, remote administration, or access to sensitive systems.
- Where operationally appropriate, block or rate-limit the identified source infrastructure and review the exposure of internet-facing Fortinet VPN services.
- Validate MFA enforcement, authentication policy hardening, and monitoring for anomalous VPN source geography, ASN, and identity usage patterns.

## INDICATORS OF COMPROMISE
The indicators below represent infrastructure associated with this activity and should not be considered exhaustive.

```
# IP ADDRESSES
158[.]94[.]211[.]14
158[.]94[.]211[.]215
158[.]94[.]211[.]0/24

# AS NUMBERS
AS202412 - Omegatech LTD
AS9009 - M247 Europe SRL
```

## REFERENCES
- https://threatfox.abuse.ch/asn/202412/
- https://www.intrinsec.com/wp-content/uploads/2026/05/TLP-CLEAR-Pivoting-on-a-malspam-infrastructure-EN.pdf
