# 2026-09-03: Cloud Data Theft and Extortion via IT Help Desk Vishing and Residential Proxies

## ANALYSTS

- Steven Campbell, Trevor Daher, Stefan Hostetler, and Joshua Riccio


## KEY FINDINGS
- Arctic Wolf is tracking a widespread data theft and extortion threat cluster we designate as PREY-0058. This activity targets Microsoft 365 and other SaaS services through IT help-desk vishing, adversary-in-the-middle (AiTM) token theft, and residential-proxy sign-ins.

- We identified a number of distinct extortion groups included in this cluster, as tradecraft overlaps significantly between intrusions and is consistent with Google Threat Intelligence Group’s public reporting on UNC6671.

- Arctic Wolf assesses with moderate confidence that the extortion group known as “Cinder” represents a rebrand or possible continuation of Pink operations because organizations listed on the Cinder leak site overlap with victims connected to Pink-attributed, organization-specific phishing infrastructure.

- Arctic Wolf observed no endpoint malware deployment or network-based lateral movement in this cluster. Actors exfiltrated data from SharePoint, OneDrive, Exchange, and Box, then sent extortion demands to victims.

- Analysis of subdomains across the lure infrastructure revealed hundreds of entries impersonating real companies. The targets are primarily US-based and concentrated in construction and engineering, healthcare and pharmaceuticals, real estate and property management, finance, and professional services.

- Defenders can disrupt this activity by detecting anomalous residential-proxy token replay, SharePoint discovery and bulk access, mailbox harvesting, and newly registered authentication-themed lure infrastructure.


## BACKGROUND
Arctic Wolf tracks this activity as PREY-0058. It has substantial behavioral overlap with GTIG's UNC6671 reporting and public reporting by ReliaQuest, Unit 42, Okta, and CrowdStrike. The cluster has been associated with self-named extortion brands including BlackFile, Pink, Helix, Cinder, and Redact. These labels may represent affiliates, changing brands, or other relationships rather than a single proven actor identity.

## OBSERVED BEHAVIOR
1. The threat actors impersonate internal IT or helpdesk personnel by phone and direct them to an authentication-themed URL, often formatted as `<victim organization>.<lure domain>`.

2. These attacks most frequently target Directors, Vice Presidents, and other executive staff.

3. The operator-controlled AiTM panel is manually gated for each victim to advance through the credential gathering process and stages a Microsoft 365 login flow that captures credentials and MFA approvals to obtain access to authenticated session tokens.

4. Stolen sessions are replayed from residential proxy infrastructure, most notably NodeMaven, often from IP addresses that resolve to the same geo-location and network (ASN) as the victim.

5. Initial sign-in activity involves applications such as “My Signins”, “My Profile”, “My Apps”, which reveal account details and the applications available to the victim.

6. After initial access, the threat actors perform discovery techniques against SharePoint and Entra ID. SharePoint discovery includes `SearchQueryPerformed` events with `contentclass:STS_Site`, `contentclass:STS_Web`, and wildcard searches using `indexdocid` for pagination.

7. The threat actors then perform bulk collection and exfiltration from SharePoint, OneDrive, Exchange, and other SaaS providers such as Box. Observed Exchange collection generates `MailItemsAccessed` events, while SharePoint and OneDrive collection produces high volumes of `FileAccessed` and `FileDownloaded` events. The client IP addresses used in exfiltration have typically resolved to datacenter/hosting infrastructure, but more recently have shifted to using the same residential proxy network that was used for initial access, such as NodeMaven.


## HUNTING GUIDANCE
- Review sign-in activity originating from residential proxy or hosting infrastructure, specifically NodeMaven. In confirmed cases, a relatively small set of client applications are used at the beginning of the session:

    - OfficeHome (the most common authentication portal that phishing infrastructure authenticates to)

    - My Signins (a page that displays a user’s sign-in history)

    - My Profile (a page that displays account details for the authenticated user)

    - My Apps

    - Microsoft Account Controls v2

- If a sequence of sign-in events using the above client applications occurs at the beginning of the session from a residential proxy address, this should increase confidence in the finding.

- Similarly, if the source location, ISP/ASN, operating system, browser, or user agent differs from the user's established sign-in history baseline then this should increase confidence in the finding.

- Look for SharePoint `SearchQueryPerformed` events containing `contentclass:STS_Site`, `contentclass:STS_Web`, or `indexdocid` pagination. These queries are being executed consistently across cases to map and enumerate SharePoint data; meanwhile, we have assessed that these queries are very rare for normal users (that is, non-compromised users) across the Arctic Wolf MDR customer base.

- Look for Exchange `MailItemsAccessed` events with the following parameters: `ClientAppId: 9199bf20-a13f-4107-85dc-02114787ef48` with `API ID: c999ed3e-27ae-4cb3-b3a2-46b056af63d3`, which seems to be a signature of the exfiltration toolkit.

    - Confidence in this finding should increase if (a) there are a significant number of matching `MailItemsAccessed` events generated in a very short period of time, which would indicate programmatic access rather than natural user mailbox activity, and/or (b) the client IP in the matching `MailItemsAccessed` events belongs to datacenter/hosting infrastructure or residential proxy IP addresses.

- Look for SharePoint and OneDrive `FileAccessed` and `FileDownloaded` events where a significant volume of these are generated by a single user in a single session.

    - Confidence in this finding should increase if (a) the client IP in the matching SharePoint events belongs to datacenter/hosting infrastructure or residential proxy IP addresses, or (b) the user agent is a scripting agent like `python-requests`, `Microsoft.Graph.Client`, or `python-httpx`.

- Monitor for newly registered passkey, oskey, and other MFA-registration-themed phishing domains, especially ones that contain your organization’s name as a subdomain.


## DEFENSIVE CONSIDERATIONS
- Require managed or compliant devices for Microsoft 365 access. Conditional Access policies that enforce device trust and compliance can prevent replay of stolen sessions from attacker-controlled infrastructure.

- Implement Conditional Access policies that block or require step-up authentication for proxy, anonymizer, and hosting-provider IP ranges.

- Deploy phishing-resistant MFA. FIDO2 security keys and device-bound passkeys bind authentication to the legitimate service origin and prevent AiTM relay of credentials and session tokens.

- Limit the scope of data that users have access to in SharePoint, using group-based access controls for departmental sites, and applying sensitivity labels to sensitive data that merits additional safeguards. The intent of this attack is to exfiltrate as much data as possible from SharePoint in order to force the victim to pay a significant sum of money to prevent the data from being leaked. The more data that an individual user has access to, the more can be stolen as the result of a single successful phishing account compromise.

- Enable Continuous Access Evaluation (CAE) to support near-real-time session revocation when risk conditions change.

- Educate employees and help-desk staff that internal IT and Helpdesk should not cold-call users to register passkeys or change authentication methods. Users should verify unexpected support requests through an independent, trusted channel, and establish a reporting path for suspicious calls.


## INDICATORS OF COMPROMISE
The indicators below represent a subset of infrastructure and behavioral artifacts associated with this activity. They should not be considered exhaustive. Behavioral hunting should complement indicator-based detection because the actors rotate infrastructure.

```
# LURE DOMAINS
assignpasskey[.]com
mfaregister[.]com
nowsso[.]com
oskeysetup[.]com
oursso[.]com
passkey-mfa[.]com
passkeydeploy[.]com
registermymfa[.]com
setpasskey[.]com

# PANEL INFRASTRUCTURE
31[.]42[.]184[.]213

# EXFILTRATION AUTONOMOUS SYSTEM NUMBERS
AS51582 - PrivateLayer Inc
AS23470 - ReliableSite.Net LLC
AS399629 - Bl Networks

# EXFILTRATION USER AGENTS
Microsoft.Graph.Client/6.0.3
python-httpx/0.28.1
python-requests/2.28.1

# SIGN-IN USER AGENTS
python-requests/2.33.1
python-requests/2.34.2

# RESIDENTIAL PROXY PROVIDERS (SIGN-IN)
DATAIMPULSE
LUMINATI
MASSIVE
NODEMAVEN
PROXYRACK
SHIFTER
SOAX
YILU

# MAILITEMSACCESSED IDENTIFIER PAIR
ClientAppId: 9199bf20-a13f-4107-85dc-02114787ef48
API ID: c999ed3e-27ae-4cb3-b3a2-46b056af63d3

# SHAREPOINT SEARCH PATTERNS
contentclass:STS_Site
contentclass:STS_Web
indexdocid>{integer}

# ENTRA ID DIRECTORY-ENUMERATION ACTIVITY
Get user flows
Get API connectors
Get identity providers
Get user attributes
```

## REFERENCES
- [https://cloud.google.com/blog/topics/threat-intelligence/unc6671-microsoft-365-data-theft-extortion/](https://cloud.google.com/blog/topics/threat-intelligence/unc6671-microsoft-365-data-theft-extortion/)

- [https://www.reliaquest.com/blog/helix-data-extortion/](https://www.reliaquest.com/blog/helix-data-extortion/)

- [https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-08-27-New-Passkey-Themed-Subdomains-Target-Numerous-Industries.txt](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-08-27-New-Passkey-Themed-Subdomains-Target-Numerous-Industries.txt)

- [https://www.okta.com/blog/threat-intelligence/behind-the-scenes-of-a-vishing-operation/](https://www.okta.com/blog/threat-intelligence/behind-the-scenes-of-a-vishing-operation/)

- [https://arcticwolf.com/resources/blog/payroll-pirates-strange-new-tides-in-business-email-compromise/](https://arcticwolf.com/resources/blog/payroll-pirates-strange-new-tides-in-business-email-compromise/)
