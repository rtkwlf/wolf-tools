# 2026-09-02: Large-Scale Credential Attacks Target Fortinet VPNs Using Organization-Specific Identities

## ANALYSTS
- Kyle Siddall

## KEY FINDINGS
- Between August 26 and August 28, 2026, Arctic Wolf observed a large-scale credential attack campaign targeting internet-facing Fortinet VPN services.
- The campaign targeted hundreds of organizations and generated tens of millions of authentication failures across multiple US customer environments. One reviewed environment recorded more than 58 million failed authentication attempts.
- The threat actor attempted authentication using organization-specific usernames, corporate email addresses, affiliate accounts, and common administrative identities. This targeting indicates the actor had access to previously collected or enumerated identity information.
- Arctic Wolf identified at least one successful Fortinet VPN authentication originating from campaign infrastructure. The authentication was followed by confirmed malicious activity within the affected customer environment.

## BACKGROUND
The campaign primarily used infrastructure associated with Omegatech LTD (AS202412) and M247 Europe SRL.

Arctic Wolf observed two sustained waves of authentication activity across multiple US customer environments between August 26 and August 28, 2026.

The campaign is notable for both its scale and its repeated use of organization-specific identities. This pattern suggests the threat actor used pre-collected or enumerated identity data rather than relying exclusively on generic usernames.

## TECHNICAL DETAILS AND ATTACK FLOW
1. The threat actor conducted high-volume authentication attempts in two sustained waves between August 26 and August 28, 2026. The activity generated tens of millions of failed authentication attempts.
2. Attempted usernames included common administrative accounts, employee names, corporate email addresses, and affiliate identities associated with the targeted organizations. This pattern indicates targeted identity selection rather than exclusively generic username spraying.
3. Some authentication attempts may have involved valid credentials. Arctic Wolf confirmed one successful Fortinet VPN authentication from `158[.]94[.]211[.]14` that was followed by malicious activity within a customer environment.
4. Defenders should treat successful Fortinet VPN authentications associated with identified campaign infrastructure as potential intrusion footholds. These events warrant immediate investigation, session containment, endpoint review, and credential remediation.

## DEFENSIVE CONSIDERATIONS
- Prioritize investigation of successful Fortinet VPN authentications originating from IP addresses listed below, Omegatech LTD (AS202412), and M247 Europe SRL.
- Review authentication logs from 2026-08-26 through 2026-08-28 for both high-volume failures and low-volume successes associated with the same infrastructure.
- Hunt for successful logins involving organization-specific usernames that were preceded by repeated failed attempts from the same source infrastructure.
- Correlate suspicious Fortinet VPN authentications with follow-on activity such as new internal connections, privilege use, account changes, remote administration, or access to sensitive systems.
- Where operationally appropriate, consider blocking or rate-limiting identified malicious source infrastructure and reviewing exposure of internet-facing Fortinet VPN services.
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
