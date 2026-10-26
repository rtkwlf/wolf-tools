# 2026-10-26: Urgent Government-Themed Phishing Emails in Colombia Delivers XWorm Through Custom-Encrypted VBScript or JavaScript and Reused .NET Loader

## ANALYSTS
- Adversary Research, Arctic Wolf Labs

## KEY FINDINGS
- Campaign and Chain: Arctic Wolf identified a campaign of judicial-themed phishing emails targeting Colombian organizations to deliver XWorm via a multistage chain.
- Loader Reuse: The recovered loader is binary-identical to one documented in a separate September 2026 UK-linked XWorm case, indicating reuse.
- C2 and Capabilities: Three distinct C2 endpoints were recovered communicating over a consistent AES-128-ECB protocol that support full remote access consistent with known XWorm functionality.
- Infrastructure Reuse. The same C2 endpoints appear in other public XWorm sandbox records under different sample hashes and mutexes, supporting infrastructure reuse across builds.

## TECHNICAL DETAILS
- Email delivery and lure. The initial VBS/JS filenames resemble legitimate Colombian administrative or judicial correspondence. The observed emails originated from Colombian organizations and used Spanish-language text urging prompt attention.
- Initial VBScript protection. The script uses generated identifiers, misleading state/configuration variables, concatenated encrypted strings, and an execution wrapper. A recovered inner layer includes a custom Base93 decoder that packs pairs of alphabet symbols into 13- or 14-bit values using a threshold-dependent rule, rather than standard Base64. Decoding then passes through keyed substitution/bit-manipulation routines. An 8-byte custom block transform and a 12-byte custom block transform use table lookups, word mixing, XOR, and rotations/shifts; 12-byte blocks are then chained by XORing transformed plaintext with the previous ciphertext block, a CBC-style construction built around a nonstandard primitive. A further AES-256-CBC layer participates in recovery of the PowerShell stage.
- Initial JavaScript protection. The JavaScript samples use multiple layers of obfuscation to conceal and reconstruct the PowerShell stage at runtime. The outer layer uses string encoding, concatenation, and dynamically generated function names to obscure execution flow and hide the encrypted PowerShell content. In one sample, the PowerShell payload is protected with a combination of SM4-CBC and Square-CBC encryption, with cryptographic keys derived dynamically from XOR-obfuscated values. Another sample implements a custom cryptographic container with integrity verification and encoded Unicode strings to reconstruct the PowerShell.
- PowerShell unpacker. The decoded script contains two protected strings, each with separate keys and IVs. It uses a custom Base52 alphabet (ten characters per seven bytes in complete groups), then derives 256-entry keyed permutation/substitution tables, including deterministic .NET `System.Random` behavior. A separate function implements a custom RC4-inspired byte-stream generator. The unpacker ultimately yields a PE32 .NET DLL and a PE32 VB.NET executable.
- Reflective .NET injection loader. PowerShell loads `RSG_UnityApp`, the recovered .NET DLL, and invokes its public static method via reflection, passing the `RegAsm.exe` path and the recovered XWorm payload bytes, among other arguments. The DLL identifies as assembly `RSG_UnityApp` v1.1.0.0 and is protected with Crypto Obfuscator.
- Cross-case loader reuse. Buschbeck's 10 September 2026 report documents the same `RSG_UnityApp` DLL hash, the same six-argument invocation, and an XWorm final payload - but with a JavaScript first stage, `MSBuild.exe` as the configured process target, and a different XWorm hash and C2. This binary-identity match supports reuse of the loader across differently packaged XWorm deliveries. A separate sample under active tracking delivers DCRat using the same loader.
- Embedded XWorm settings. The decryptor derives a key from the MD5 hash of the mutex string, then applies AES-256-ECB to the Base64-decoded ciphertext to recover configuration values.
- C2 framing and functionality. Communication uses AES-128-ECB to encrypt the UTF-8 message, then prepends the encrypted byte length in decimal ASCII followed by a NUL byte. Received messages are decrypted and split on the `<XWormmm>` delimiter. Initial INFO beacon traffic includes an identifier, username, OS details, group, installation date, elevation status, webcam availability, CPU/GPU/RAM specs, and antivirus status. Observed commands include `update`, `DW`, `FM`, `LN`, `RunShell`, `$Cap`, `plugin`, `savePlugin`, `StartDDos`, and host-file operations; plugins can be loaded as managed assemblies.
- Infrastructure relationships. The three C2 endpoints above also appear in recent public XWorm sample/sandbox records. Two Triage records published against the same endpoint list carry different mutex and group values, consistent with separately configured builds rather than a single shared sample.

## HUNTING GUIDANCE
- Windows script and PowerShell: Hunt for `wscript.exe`/`cscript.exe` spawning PowerShell, particularly hidden or encoded commands, and for VBS files containing unusually large concatenated encrypted literals together.
- Process and memory: Correlate anomalous `RegAsm.exe` execution with upstream PowerShell, creation of suspended processes, remote memory writes, thread-context modifications and CLR/network activity unexpected for registration workflows. When possible, scan recovered memory for the `RSG_UnityApp` DLL SHA-256 or characteristic method metadata and inspect for hollowed image anomalies.
- Network: Search DNS, firewall and EDR events for `loganwolverin2042[.]webredirect[.]org` and outbound TCP/4521, especially from `RegAsm.exe` or a process chain originating in Windows Script Host. Network inspection may reveal decimal-length-plus-NUL framing, but encrypted payload bytes alone are not self-identifying.

## ADDITIONAL RESOURCES
- [Buschbeck — XWorm Attack Chain: JavaScript, PowerShell, Reflective .NET Loader](https://blog.buschbeck.dev/posts/2026-09-10-xworm-full-chain/) — Analysis of UK targeting file with same loader and different version of XWorm and C2 (2026-09-10).

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# C2 DOMAIN AND PORT
loganwolverin2042[.]webredirect[.]org TCP/4521
ukranieukranie20222022[.]duckdns[.]org TCP/3008
45[.]92[.]1[.]127 TCP/1177
77[.]110[.]114[.]115 TCP/3008

# URLS (Download second stage)
https[:]//cdn[.]filestackcontent[.]com/B7hA66RuGnT1LRjBp2Ax
https[:]//cdn[.]filestackcontent[.]com/OjJYVfNcSaCemmakSzPg
https[:]//cdn[.]filestackcontent[.]com/dXsER20oSBCJeqtF4yq7
https[:]//cdn[.]filestackcontent[.]com/3LI5K6STzaI8VOvBgmga
https[:]//ik[.]imagekit[.]io/randiatmv9/NOTIFICA_ACTO_PROCESO_TUTELA_PDF[.]zip

# SHA256
57ae80bcc2028621086781da603110b8d6abddb840f4ba0f3395e40c8b1cbf74 # Downloaded file B7hA66RuGnT1LRjBp2Ax
6b5487998547ea629340689b76a6e7b3bdcd5f605a452ede5294fe2053b952d9 # Extracted file PROCESO DISCIPLINARIO_ RAD_00470032.vbs
fe34be2cee9ba40f0e6ce4dc509ba85b79851ca9d08bf8a878602300486674e2 # RSG_UnityApp .NET loader DLL, identical to Buschbeck report
ea0832705c8f8c368f4d4fb9eb15ddd64df1859e12af19a2e9b13280b2139bbe # Payload XWorm
554b95378744def1b8024bd01bd28f982bc093d29d847548fd0e1316e1fc19bb # Downloaded file OjJYVfNcSaCemmakSzPg
50897e5d87ad9e05bdf9bc2cbb5b9fe1ebacb1c9a2b55a566d4ba4d10e035ab2 # Extracted file ACTA_NOTIFICA_TUTELA.js
2d45e12ed77718927dbc36fa81f61333c32a549d214a651bc12043acef7fe260 # Payload XWorm
a6c17d8b864940327a98e2f3b7d3b57360d2a05ce85d48cdcd38a1b5bd3a7442 # Downloaded file dXsER20oSBCJeqtF4yq7
2e91c4624bc0fcc7674bcc80d778067913daa07a3516acbfc1d08ba76ce1737f # Extracted file VER_SENTENCIA_ACCION_TUTELA_PRIEMRA_INSTANCIA_200156001.js
35b48c18d49c8c714935af51e01660da3efb5e239bc2fd7136727220e6f41130 # Payload XWorm
0f202abc036b66c3fcb993d58631c63207f6ea3ac56f87051855ad2af35c0292 # Extracted file NOTIFICA_ACTO_PROCESO_TUTELA_PDF.js
daf6416515b7503a1572ad4ac3a0057585238583c37eaa23d11468d10b5283a5 # Downloaded file NOTIFICA_ACTO_PROCESO_TUTELA_PDF.zip
7020fbd08fdde0a2c1a9c11ec11bdf3be9a6f3b58a78fbfe907fccc11eb404ca # Payload XWorm
db0e4f1afc7d9036c4561a582af57dbe0f0826b03b266c2cb99d2fb07fc5c242 # Downloaded file 3LI5K6STzaI8VOvBgmga
e514e981d7db3f74c878d7eab9ed6d1aaa3c37cd9cd239f86abcc2df6d2711ee # Extracted file CUMPLIMIENTO-CONTRATO-RADICADO.js
8da000dac095000fb4167db27aaf2810ac13a1e0815736ead22d93fefa5bb90e # Payload XWorm

# XWORM CONFIGURATION SETTINGS DECODED
Mutex: nLWzeTbvXzjAxooJ
Configured filename: USB.exe
Protocol delimiter: <XWormmm>
Traffic encryption passphrase: <1234567890>
Group: zzzzzzzzzzzzzzzzzzzzzzzzzzClientOTHER
--
Mutex: bqHmkD44JB1XWaPz
Configured filename: USB.exe
Protocol delimiter: <XWormmm>
Traffic encryption passphrase: <1234567890>
Group: MAXI073
--
Mutex: ELxcVIaozcn8SSiv
Configured filename: USB.exe
Protocol delimiter: <XWormmm>
Traffic encryption passphrase: <1234567890>
Group: COLEGIO
--
Mutex: DiIAYaBQsJDcp2xo
Configured filename: USB.exe
Protocol delimiter: <XWormmm>
Traffic encryption passphrase: <1234567890>
Group: MAXI064

# SHA256 (Separate third-party samples reportedly associated with the same endpoint)
cabb31719b9297b71e446fcdd4bdf4dcb9fb3f93f4d7eb8054cd7e82d11372b3 # MalwareBazaar-associated sample

# IP ADDRESSES
31[.]77[.]220[.]100 # Resolved loganwolverin2042 on October 14
13[.]143[.]144[.]177 # Resolved loganwolverin2042 on October 12, 13
45[.]88[.]186[.]191 # Resolved loganwolverin2042 on October 19
77[.]110[.]114[.]115 # Resolved ukranieukranie20222022 on October 19
45[.]92[.]1[.]127 # C2 for one of the samples
77[.]110[.]114[.]115 # C2 for one of the samples
```
