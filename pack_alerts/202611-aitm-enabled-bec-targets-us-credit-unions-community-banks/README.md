# 2026-11-13: AiTM-Enabled BEC Campaign Targets U.S. Credit Unions and Community Banks

## ANALYSTS
- Jens Pose, Steven Campbell, and Ross Phillips

## KEY FINDINGS
- Arctic Wolf has observed a sustained business email compromise (BEC) campaign that relies on adversary-in-the-middle (AiTM) phishing to steal Microsoft 365 session tokens. Activity dates to at least February 2026 and sharply increased from late October 2026, with most intrusions occurring between October 21 and November 9, 2026.
- Targeting is concentrated on U.S. financial institutions, with most affected organizations being credit unions or banks, or serving the credit union industry.
- The campaign spreads by abusing trust between peer institutions. Compromised mailboxes send phishing lures whose subject is the victim institution's name (for example, `<Credit Union Name>` or `Fw: <Credit Union Name>`). At least one victim was first compromised by a lure named after a different credit union.
- Nearly all post-compromise mailbox access came from one IP address, `64.227.207[.]20`. This is a shared Check Point SASE (Perimeter 81) egress node in DigitalOcean address space, not infrastructure the threat actor owns.
- Once inside, the threat actor targeted wire, ACH, Fedwire, FHLB, cash-balance, and loan-funding correspondence. In at least one intrusion, they sent a series of outgoing wire emails from the victim's mailbox over five days and hid the evidence by moving replies to the RSS Feeds folder and hard deleting the threads.

## BACKGROUND
BEC remains one of the most financially damaging threats facing financial institutions today. Wire and ACH operations staff at credit unions and community banks are high-value targets because their mailboxes hold the templates, approval chains, and counterparty relationships that a threat actor needs to redirect funds. AiTM phishing kits relay the victim's authentication to Microsoft through a proxy and capture the resulting session cookie. That lets the threat actor replay an already-authenticated session, which defeats push-based and one-time-code MFA.

This campaign pairs that technique with a commercial SASE service and residential proxy networks. Its sign-ins appear to come from a reputable U.S. vendor address or from residential IPs near the victim, which reduces the effectiveness of location-based Conditional Access and “impossible-travel” logic. In at least one case, the threat actor's IP fell inside a named location that the victim had allow-listed for traveling users.

## OBSERVED BEHAVIOR
### Initial Access
Victims received phishing emails that led to credential-harvesting pages imitating Microsoft sign-in.

In the intrusions we examined most closely, the victim's authentication was relayed through a residential callback proxy. These proxies were tagged with commercial residential proxy networks such as OXYLABS, NODEMAVEN, and PLAINPROXIES, and a different proxy node was used for each victim. The proxy sign-ins showed an empty browser user agent and a Keep Me Signed In prompt (`50140`), which indicates the session token was captured.

### Token Replay and Persistence
- Successful sessions were recorded as `singleFactorAuthentication` and were frequently non-interactive. In one case, a single refresh token kept the session alive for about five days, with new access tokens issued roughly every four hours.
- In multiple intrusions, the threat actor registered its own Microsoft Authenticator MFA method within minutes of first access, or visited My Profile, Account Controls, and My Sign-ins to try to do so.

### Collection and Fraud
- Mailbox access began within one to two minutes of the first sign-in, mostly through Outlook on the web (`Client=OWA;Action=ViaProxy` on `MailItemsAccessed` events).
- The threat actor searched and read financial operations content, including wire requests, Fedwire and ACH files, daily cash and end-of-day balance reports, loan funding, wire templates, and member data spreadsheets. One intrusion recorded more than 24,000 mailbox item accesses.
- In at least one case, the threat actor followed a repeated pattern: draft an `Outgoing wire - <reference>` email with a PDF attachment, send it, immediately move the sent copy to Deleted Items or RSS Feeds, then intercept and hard-delete replies, including one in which a recipient questioned a wire.
- The threat actor modified attachments on existing sent items, and in one case forwarded an internal compliance document to an external address.

### Defense Evasion and Propagation
- The threat actor created evasive inbox rules with short, generic names (`new`, `news`). The rules move incoming messages to RSS Feeds or Archive and stop processing further rules. In some intrusions, no inbox rule was created and the threat actor manipulated messages directly.
- The threat actor sent bulk outbound phishing (in one case, more than 1,000 recipients across nine submissions). They answered recipients who asked whether the message was legitimate and deleted bounces, autoreplies, and warnings.
- In one intrusion, the threat actor purged Deleted Items at scale, attempting to delete roughly 61,000 items.
- The threat actor compromised multiple accounts at the same organization in parallel. In one case, two finance users were compromised five minutes apart.

## DEFENSIVE CONSIDERATIONS
- Require phishing-resistant MFA (FIDO2 security keys, Windows Hello for Business, or passkeys) for finance, wire, and executive users. Push and one-time-code MFA do not stop AiTM token theft.
- Enable Conditional Access controls that bind sessions to trusted devices, such as requiring compliant or hybrid-joined devices and Token Protection where supported, so that stolen session cookies cannot be replayed from threat actor infrastructure.
- Restrict MFA method registration (the "Register security information" user action) to trusted devices or locations. Require re-verification before a new authenticator can be added.
- Review named-location and travel exceptions in Conditional Access. Avoid broadly trusting shared SASE, VPN, or cloud-hosting address space.
- When an account compromise is confirmed, revoke all refresh tokens and sessions, reset credentials, remove any MFA methods the threat actor added, and delete malicious inbox rules. Keep the account disabled until all existing tokens have expired.
- Disable automatic external forwarding and limit the ability of non-administrative users to create inbox rules that move mail to rarely used folders such as RSS Feeds or Archive.

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# IP ADDRESSES (Threat actor mailbox access)
64.227.207[.]20 # Check Point SASE / Perimeter 81 egress, shared infrastructure
64.227.206[.]3 # Check Point SASE / Perimeter 81 egress, shared infrastructure

# AUTONOMOUS SYSTEM NUMBERS
AS398391 # Check Point SASE, egress for 64.227.207[.]20

# USER AGENTS
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 # Primary mailbox access

# INBOX RULE NAMES
new
news
```
