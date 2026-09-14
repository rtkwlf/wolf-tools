# 2026-09-14: Spear-Phishing Campaign Uses Lua Scripts to Deliver In-Memory Infostealer Targeting Organizations across Central and Eastern Europe

## ANALYSTS
- Alyssa Newbury, Dmitry Melikov, and Steven Campbell

## KEY FINDINGS
- Arctic Wolf Labs recently discovered a phishing campaign targeting organizations across Central and Eastern Europe spanning healthcare systems, industrial manufacturing, and critical infrastructure.
- The infection chain begins with a phishing email containing a malicious Excel attachment. When the Excel file is opened, it initiates a multi-stage delivery process, retrieving an HTML Application (HTA) payload.
- The HTA payload downloads via PowerShell a heavily obfuscated JScript payload that then initiates a downstream LuaJIT and obfuscated Lua-based script. The JScript drops a LuaJIT interpreter renamed with a legacy `.pif` extension alongside an obfuscated Lua script disguised as a TrueType font (`.ttf`), then executes the interpreter with the script.
- The Lua script bypasses ETW/AMSI and loads Donut shellcode, which unpacks and executes .NET Reactor-protected components in memory to deliver a final infostealer that collects browser data, cryptocurrency-wallet data, and Discord data according to panel tasking.
- Arctic Wolf Labs identified two distinct delivery techniques feeding the same malware execution chain: a templated lure cluster with matching persona, order reference, and subject-line patterns, and a separate Serbian-targeted case that hijacked a genuine, pre-existing business email thread to deliver the identical payload chain.
- Arctic Wolf Labs identified a shared lure-generation template reused across multiple impersonated brands and at least five countries, all delivering malicious Excel attachments that produce the same malware execution chain. Delivery technique varies by case, including injection into a genuine hijacked business thread in one instance and fully fabricated multi-message reply chains in others. We identified a leftover boilerplate artifact confirming these lures originate from a single shared production template rather than independently crafted messages.

## TECHNICAL DETAILS
- Threat actors used procurement-themed phishing lures to deliver malicious Excel attachments with requests for business services quotes and delivery timelines.
- Opening the attachment initiated a staged infection chain that retrieved a malicious HTML Application (`.hta`) payload. The HTA executed an obfuscated VBScript and PowerShell script to drop and establish the next stage of execution: a JavaScript-based loader running natively via the Windows Script Host (WSH).
- The JavaScript loader drops and executes a binary as a legacy Program Information File extension (`.pif`), which houses a compiled LuaJIT runtime engine, passing an obfuscated Lua script disguised as a TrueType font file (`.ttf`).
- The `.ttf` file is an obfuscated Lua script protected by a bytecode virtualization obfuscator with layered string encoding, junk code, and a self-integrity check. Executed by the LuaJIT engine, it patches and blinds Event Tracing for Windows and the Antimalware Scan Interface before staging any payload. It then allocates memory and maps a known memory injector (DonutLoader) directly into the running process.
- DonutLoader unpacks and executes the core payload, an infostealer, in volatile memory, with .NET Reactor-protected components observed in the process. The stealer establishes command-and-control communications, profiles the infected host, collects browser credentials and application data including cryptocurrency-wallet and Discord artifacts, and stages the collected data for exfiltration through chunked file transfers.
- **Lure delivery variants:** A shared lure-generation template, built around a reusable persona ("Olga Sanguinetti M., Adquisiciones"), was observed impersonating at least two distinct companies—Denmark-based global inspection, verification, testing, and certification company Baltic Control and Czech-based engine-solutions company Auto Linea—across four countries (Poland, Romania, Ukraine, and the Czech Republic). Each referenced an identical order number and delivered a malicious Excel attachment named for that order number and translated into the target-country language. Notably, a boilerplate legal disclaimer referencing "Baltic Control A/S" persists unmodified in the Auto Linea-branded version of the lure.
- A separate case targeting a Serbian organization used a markedly different delivery technique: the message's `References` and `In-Reply-To` headers suggest it was injected into an existing business thread with a purchase-order reference and prior correspondents, consistent with thread hijacking rather than the fabricated-chain pattern above. Despite this divergent delivery approach, attachment analysis confirmed the same malware execution chain in both the Serbian case and the three-email cluster, indicating a shared payload pathway behind two distinct social-engineering techniques.

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# IP ADDRESSES (Observed HTA and JScript-delivery infrastructure)
192[.]255[.]195[.]153
192[.]255[.]195[.]131
192[.]236[.]217[.]77

# C2 IP:PORT (C2 of the implant in memory)
38[.]49[.]216[.]102:21334

# URLS
http[:]//192[.]255[.]195[.]153/122/csc[.]hta # HTA retrieved by an observed Excel attachment
http[:]//192[.]255[.]195[.]153/122/weneedbestthingsforbettterways[.]js # JScript download embedded in an HTA

# SHA256
47900ab11891a81382cb6389f592cbd29cfe2bbe0bd6fa90fc7c819132d747ac # Outlook-message delivery artifact
44a8fce9763c565d05fd91a31591955846fb3a399bcf20a0d18fc62c87336bfe # Excel attachment shown in the email screenshot
59b494eb143680ce0fbf7f36189fbc8e3b1a963ffae95990932227c58705e6ce # HTA downloader
229c85bfe51e9d0df6578978b4f5937ccfb135d6122feb8b3a4a1dd5badc49b8 # HTA downloader
bfd99a56305040b3b228ffee404d44272c48e89347f5959dca235a62f88b1822 # HTA downloader
cf892f3d631128a39e0e93d4227b92490940f171e54f07541d9cf8232a8235fb # HTA downloader
fe28a9662c668d169a1c53c1f18dca89af08ef7aae39e070f5d316604d877793 # JScript file
ae3beb80fa2c89d3753f229b9b71f4ee4f8b04737b62a7e3799cbf883878e6e2 # Lua script TTF file
52f0c0230b580e2fdf53a378b5c6d0db9829af900dae43e0df8f18635cd9f0c1 # LuaJIT PIF file
e989abfe8e16c9bc5ca660974cd49fbe443d5fd31e014af7503f2ea916b9070d # Msfuxk .NET injected infostealer payload

# FILENAMES
weneedbestthingsforbettterways[.]js # JScript payload written to %APPDATA%

# MUTEXES
QdlujYEgsOMM7p8ZxZ8j
```
