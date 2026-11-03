# 2026-11-03: Grandoreiro Campaign Targeting Multiple Countries in LATAM

## ANALYSTS
- Adversary Research, Arctic Wolf Labs

## KEY FINDINGS
- Arctic Wolf is tracking a recent Grandoreiro banking malware campaign targeting users in (at least) Argentina, Chile, Colombia, Mexico, and Peru through country-specific phishing lures tailored to each region.
- The phishing chain relies on recently registered domains and layered redirection to hinder detection.
- Next stage servers are rotated frequently, with each server generally active for one day, except over weekends. These servers provide the configuration data needed to retrieve the payload.
- The final payload is retrieved through a Domain Generation Algorithm (DGA) seeded with the current date. During recent observations, the generated domains resolved to the same IP address.
- Analysis of the web infrastructure and loader revealed support for five different languages, including Spanish, English, Portuguese, French, and Italian.

## TECHNICAL DETAILS
- The campaign uses localized phishing lures, primarily in Spanish, with some observed using Portuguese even when targeting Spanish-speaking countries. Themes include invoices, administrative process, tax information, and legal notifications. The emails direct victims to a Google URL-shortening link (which starts with `share.google`) that initiates the infection chain.
- Clicking the `share.google` link redirects victims to a webpage that detects their language and displays matching redirection instructions. The page also filters mobile devices, informing victims that the content is desktop-only, before redirecting to a second domain that repeats the same validation and redirection.
- The next stage presents a language-specific interface and masquerades as a SharePoint document-sharing portal. While most observed samples used a SharePoint-themed template, some variants used a DocuSign-theme.
- The final redirection stage performs additional access and download-limit checks before retrieving a MediaFire-hosted payload.
- The downloaded ZIP archive uses a deeply nested folder structure populated with two legitimate PE files and two benign PDF documents. A VBScript file located in the archive's root directory acts as the primary payload, employing junk code and multiple layers of obfuscation before reconstructing and launching a Delphi-based loader.
- The loader masquerades as a PDF reader and is artificially inflated to approximately 80 MB through the inclusion of a large BMP file in resources. It contains obfuscated strings, including a hardcoded next-stage URL; the loader resolves a daily rotating No-IP-hosted resource (a third level domain resource) via DNS over HTTPS (DoH) to Google, retrieves the next-stage configuration, and derives the communication port from the resolved IP address.
- The loader requests configuration data using a sample-specific key. The returned configuration contains the information needed to retrieve the final payload, including its download URL, expected file size, and executable name. The payload is hosted on the same infrastructure but delivered over a different port. The associated IP addresses and services typically remain accessible for only one day.
- The final payload is delivered as a ZIP archive protected by a cryptographic transformation that uses a hardcoded key and appears to implement a customized variant of RC4.
- To establish command-and-control communications, the malware obtains the current date from public time services and transforms it into a seed for a domain generation algorithm. Arctic Wolf observed the resulting DGA domains remaining active for approximately five days before being replaced. Despite the domain rotation, the generated domains consistently resolved to the same IP address.

## HUNTING GUIDANCE
- Hunt for `wscript.exe`/`cscript.exe` executing `Shell.Exec` and for VBS files containing unusually large concatenated encrypted literals together.
- Search DNS, firewall, downloads and EDR events for `mediafire[.]com` and associated No-IP domains and other free third-tier DNS services, along with the IOCs provided below. Additionally, search for HTTP requests whose URL query resource is an unusually long string and whose response is also a long string.
- Hunt for DNS over HTTPS (DoH) requests to public resolvers such as `dns.google`, `dns.nextdns.io`, and `dns.alidns.com` that contain DGA-generated domains resembling random alphanumeric strings. Such activity may indicate attempts to resolve Grandoreiro-related infrastructure, especially when observed on systems that do not normally use DoH.

## INDICATORS OF COMPROMISE
The indicators below represent a subset of the IOCs associated with this activity and should not be considered exhaustive.

```
# SHA256 (ZIP file containing the loader)
f5a28ca724e54684f99cf525fa3cbaa800214425ad4843e82a76e6a4e7024e9e # 0Tram_ZJKVFec104Q-trehclEvid.zip
c4fa6460de379b6461a0e9739ea2042bb03435b0011814d2ce8200ca28f52756 # 0-fnhmi325076NVEHAJKTJNomUFGBIEvid_Fol.zip
1dd9de75950364bdc46b51680cdf479e969ab64b34e3d21f55c966baa076dcdc # FHAKZNotnjhl97128-6LZ5456544-Ratif.zip
f8d6f66ecd35ee4fd1660c26470a52148d93a1f8a8dfe6c7a0df24afefaab293 # fiupjLote_Carg9807TFBGMP-5GNND1_RDAC8HJ4.zip
36ad5d74f2b1da5a8405f7ce682597439e56fdd584b02b78905d7a7b28502bae # I8EL97DspIXSGQOfcl-290209D0FQ124911248.zip
ac70ca75e70d642f5dfcdf51ec8c7c6ef661c56f531e0b3dd66b789388d02945 # Fol_ecagProv-Cial_QMBLKCMLPN6R1907O6SEO.zip
b2616512d8960e814ac2d37a4a1da0fe2cc1d7b1303bd58eaf1dc36d1b88c4b0 # 0Tram_GQKDFecZYOJ6-rgfqkeEvid.zip
a8bef52b928f0ed88e2c0f8f054b907221bf11fec4166eadc811a7e4ff24caa6 # Aut-mgpgcCial-66968-vulpbz.zip
e17ea3387e68b76bab90de5548b1187b0ff2dadc4a519f55a7dcaf617c2e8fcf # 0Tram_KFMSNFecZYZMY-mcdhhEvid.zip
3b2fdffda559d27780f85bf93878ff158474b4a9f3b2d22bdd803d444c4b3f92 # 57766NotJOXPDN4BR-VGEELK-MFOZVUVRJCier.zip
2b42b7c19d45254c9da53121640a84bc680d953eb7816d05a9403a0cca7b6146 # Ord614725_55998Fec-moyvyz.zip
687373c174b1c11ce2ba91da10186438f38077fca378ac7f9e51554e1f2c10b2 # 0xhaycxArchFF4IVigCJQQ5OT1fyvekq-Cier-E3TB.zip
2c97fd2466af457348ee43aa79d08716b1328f0553bbacdd61ce75d70024fda5 # 0znexxbncsvHZFCAkzhdsAnex2497_gkxaDigi_Arch.zip
ad3facdec85f9a40a0f77bc8882e0d45dffc4d1187666074ff5bd4a0cb0e8e1f # 0_1NBCX-T7641Memo13017AprobSJ569LKKL.zip
01dd74b23fef65929b872fd6c8fd55b5a929f9c8cc9b51fa146884268501d758 # 0-AcuerSDEJCY1601ConcsfuvLIYBRQlykld_Prov.zip
b48a183ac090ad385bd7cdd303208120b3269966d25ef6af4e405c35929b0b31 # 0_6MJ7-23HBMemo0077Aprob489RDRECA.zip
efe3cac11c303fbc1b331ef511a93e8dc767a18859492e1395f2cec2da29c739 # Ord768201_61312Fec-sqymr.zip
81b70f94e27bd19eed0bef334ce51908cd30958dd5f51b38e885a04ee1141c75 # 03ZYE4VisuBNOBVrfc-07G2XI6_yulcpn26PDYoydj.zip
4139ca119ca0967f0fb4946796a3df4e0e1b2d8833f89ee25d1eeea192e37d3b # 6CO2Pag11026AperPXZIXU-Valid_TYXRPCbdir.zip
ce5d2e8ff9e95c88e6c9946bb80f575376bb137a13d363d368c7145e84783ca0 # 0Acuernaicokvvtv_XIBAKDefOYR76C-intoop879940Com.zip
530c5dc9362ac2e53392be1e0f56ad2419e2cb6f2a9e1371334b99e40f8061ba # 0yubfplztpnVDGYEHzaejiAnexOHLE_zrogqDigi_Arch.zip
6d5a97dff31a8e9cffed36752bc39fc452867beaa0b71626a35b436c86225c17 # 0NQRZMOReg8304_Cita-4048CMN52KAdm.zip
89b11c2f780b625e9ed6cc0715d57ce095ac7acf669ade726900d7f68b8b279a # bgxigLote_Carg30381SUUJO-9FUND_6X51AYQ85.zip

# SHA256 (VBScript files that contain and launch the loader)
a7628997ab21a01326f66733237adff9afd4f95576e1c2221e40bf3fe0041ba4 # Fact05490EV7DQIQP_F9HY8X_Conc_Com-Pend4025M4-fbjsrs.vbs
406049b1c2aa48a6557fb1d0f2bc0c4f26f4814fb0fd871752940247875aca78 # Resol-Det_Ratiftaxz_CierE36XF3TTEMConcssiaqh0-565923.vbs
64936013cbf849d1418da45352e160b6e3d6a951330ae4c4849114fe55c11ed0 # Bal-afoosiVisurzmqnltprrq_0RS6L-GOMJDD_312552Arch-Cop.vbs
82d91be3e1ecdc112f594f123e3265d18550a2cd62ea64864133d93a0b10818b # 0YXVUXufpfCompVSCQGC-Tram_DigiKU4Z09Cial4399-Prov.vbs
e2d23532675f34e7ab20d528309a13e47040cb0d442c696902432773dd7bf865 # MQHCDRFol_Judi-Q7VVMValid-ExpSGZBC-Firm_4ZGGHN013C.vbs
83faef0b4a369cb331f06579b550f1e13950ece3805e2e6e9159b2744de35e29 # Ord_Anul_Arch-kzoxvfRecep-GZCBD32240CitaXGNUNE21845.vbs
b4ff1ff38d00c31e88d5f03900a64fca3959214c9fa318212c768ae658632d31 # TUNLPresNOQHOrig_RefZOGSCEvidECT1PYnimsv_339968Def.vbs
151c400006839f0cb470741ab841e80ea759c6f0d0cd561dda5033deaa4019c6 # DspalhluCita-Conc09815CSCD8-Aprob-Ratif896117151.vbs
db98dbccc52397a7ea0efd2e7f5defcbd8b06ec732e889daaebcbdab72a1eb69 # 0BRMXR696165Imp_Cial-262003VFSNYPlbbo_Judi-3QK7IRatif.vbs
1bae6e58786d42ea526ec578092c0c888a6c9b6786b43b023d3c8a672a5aae77 # xxxgyv733516Ord_zkjppnJudi-92630Tram0VrfcVSEPZF9629Det.vbs
06d2a0e9aec990425b35a8b052a133c40db91d355ed50f78bd74ed652179a3ac # Dicthnqn-Prov_Visu_teei033424UNB2Digi_Aprob09616.vbs
04b3fd459ef28d7cc3e368204a9288ce57643d995c6608ca15e75eff598276f2 # Tram-ConfLPXY_UKZUXRDsp79588-Recep2153Visu-2674.vbs
686d122f3abe6bd6fce60907b2bfb6dd9827ac110a577435ee95dcc97a37127e # 428034103Pres-0Conc_Adm_574HProv-Anul7162G58U.vbs
c49da2f1c44701f26330a38a195faf9f07cebfe52c69a74f5a506ec92da5d32c # 0-FH0R2Proc-Cita_Carg1VEZZZKIN7403854959_Prov_ynuksuCom.vbs
e0b4bb164212fd9e3d8b87fddaf391ef647195c6e610538d371b677b8ba8c922 # 0Exped_Anul_Valid681383485901JudiIVJK422790Aprob6LG12.vbs
631e9cb1d4651d5d791abba1f9ea69acd50fd4f70713064a24d7afdf698d31c6 # Sol0Citavhgkzx-Recep-DFXQRatif83475Penduoye_oyfcq.vbs
a6d1e14f5df1a4dd40eefad6931c51dc31cc04ab809358447a6cf86eb893a4a6 # OrdadbzerDigi0Fec13739-XTQINEUOMR0SZMPend-RSSCOrig.vbs
25c1ec9fed398d1297e2811de1eeb734285419e49667a0ad51059a52f4a23b1b # 0SPKB250P_Ser_Vrfc737135DIEHTCFol-nlucokDigi_7368Cial.vbs
ba033464feb3ec0d0fcea2feff5599854f8391fb0367472e1663ec0bbd16a62c # 0_CertO4ZV0OrigGZLZAJ_FR7ZCFoltyurmnAdm_733084126Visu.vbs
2f0742e10a9d2ce1344f705ebc191562d6634fb38401afdcb7d7c4810821127c # 468O834975267621-0Visu-Adm-CopZFPSECompefojValidmmrh.vbs
687e9eb1222abd027611797e74d753cc60d7bb1dc2aae0fe99b6f8d919014dd5 # 0Lote5F84-Aper8AQAA_MARHCial_Exp1KD72VKDITToybaebCom.vbs
52d3e4d82ee81aaf1cba5b68cf66e275b1abe0592c84ed6bf2e1a97359b50c5b # 60926Sent-0Firm-Conf25785_Ref1346ValidPSHXM_rjdoqy.vbs
5caf8992790d57c7664f8d9ebc526997f448707851311d8d03126ddde9c82ad1 # Conv_ztvmhJ6G3OValid-Carg98XY_Ratif0_gmztgu_Judi.vbs
451eb2e43563386cf00cb7ce25033777b91a883bcdd874a4f5bab1ea427360ae # ZGMMYAnex_XXGI44994-Conc3AG229-Anul_Dsp_RecepAU8196.vbs
58e8b96b873825e58045a562d1a0b8f7bb9e794d225391755862bf736b6e6d98 # 0Acuer-AnulG2I3-FolKO69_EmisYMSKybntrReg_E59M4.vbs
78bac189c470188e135606cac05e171b3f0176aa64b774e899fe660d6011a662 # 395449965SerCZXR-Arch-cjaaDigi_Conf-0-Cita7M10.vbs

# SHA256 (Loader samples)
41f8ca4c55b9daa3c86a03e686ac376c840a4632b8091059bd5e3035fd3c8f73 # RAgHsSiFzMdO.jau
f8be1c1a6d0d606f6a4187bffcfb34d5b75c529c1fac72317107d685073d8c40 # oYMZnCrDDeQar.cuc
6a881831c313918485d50187440294a6951dbb2b5353b291ead0fcd01df9bc73 # CrMnaEkcjEMHNDopnYHc.stf
6d552f05fbc084b03b642244b461ac993508b62da618a66e91734ca6b48b61e9 # bGAfEOYQzLsHcvrgNQ.qhc
76e0463f6d157e9a76960e26effd97bf768dab1ac8c6085b37180d48ac17e04d # fMeisAtYRRBn.eqw
5a56df2247796a8ca0b21491dd30d36f34e38e77407dc9a1818e839aea35e301 # rrEXEIYPnYuPYfpgjVPQO.qla
c41496fb1d89769e31435b9ae8a2df7eb93bd0153898af6a34554ce57bd80f4a # JgMCrzUQkyvtrDQsfR.syj
219893c837ee5e29d0191fe7386863a5dceb22532acd623e861562ecd67f5574 # xCBPLIbzyqBqKhuZECg.pgg
edd08554e791eabf14fe7ab48834328e19d39842058b3935ac4dfb16d6c6fe27 # tmp/DzPtPZTJdvMCKguOdg.vdo
7ba3b6cf5e3a1e943b7e346e9ad9fdb7bcfa2e6e1a2e27497075a5e5796237df # sVutJiQPopE.yzh
e4300f890197fce9296aca92e8e002c1a5ed87cd5afbd96bdb15ffba97bd5ff3 # kCkhrNVCVjjypxSgtTmN.hnc
adf517c6b90388c546ee6dffa3e146b802071e3439ce8b5d27ad266feca50371 # ZMxJzSatrENdzaTRQBylf.dfq
d6bdce331db07141ade7dad70c8a2b022c093388cca8ec0fd55b040cdf5d9c5b # ONzUMYZfBMAr.xhw
29d03a08d91c3ce7648b4be5aadcc2d89b801170b85a886bd311af288ff2dc33 # hHHkatOdLenfosh.eij
c3467b34be7fe079941af8cd6be82e7674edddb7020b456bae1fd2ebef51f9f1 # TedfBMUzDxkqtzH.dtc
69670152e8047d4bebe264d8b7130a204296dcbfb993bd8296eda0f7a1f3a7f9 # jNIrnAHoNYtvTOlLJlI.jeg
a86b286624a6ac5dd067ad9c5c24187ede7486f60204498bcb42b2e687446599 # PjfnFJMsQUVgmit.cjy
288fe8d79cb3a7ab320dd9436357d65f7b145e307e05e846e8442808f4174416 # ytEeZacirgu.xby
b80ddee3d1e2dad43f5e4b375a90779ec0cb622ae793ab5b722de252cf97349d # eYuKURhxlkJ.tfp
e91d6a019cf288632ce2d9ee57e9acefe309fba26b2118bce5fd5372b49e60ce # THdIrmVnadyHuOBELjJNj.slt
5000646e0ef7334fa80b6a713ae11ccd465e9c8794bd6673ebfa07b93dec75e1 # FtIQlFUQRZgmtdsvNVvMB.rlz
e28d9a3096d3ec2b96489aca7d91c027dbb5650092f30e75796fb2fc63e17ec9 # RNAahxoZjrjfq.eor

# SHA256 (Payload packed downloaded)
817b510a31c81ebaa823d124de6f253a10be010546ab2aadddd4792f4fe476c7 # RalinkRendererLPLbCleanLive.xml

# SHA256 (Payload unpacked)
04ab52e52ff5b51afbad2870f2b27f0d88a34244a0a4ec3a092370f56a7afb1b # RalinkRendererLPLbCleanLive.zip

# SHA256 (Payload EXE)
d0e9e2e607e00f4afb6895428eef153bf9b3b1bf69954f0b4660e8bcb2c4242c # RalinkRendererLPLbCleanLive.exe

# URLS (MediaFire URLs to obtain the loader)
https[:]//www[.]mediafire[.]com/file/v6rnxtaxrjrbbi9/file
https[:]//www[.]mediafire[.]com/file/rwabheeh2d3ol02/file
https[:]//www[.]mediafire[.]com/file/z65q3m81v4n2b93/file
https[:]//www[.]mediafire[.]com/file/ven010pkehm5mga/file
https[:]//www[.]mediafire[.]com/file/4tt9cd2xidb0afx/file
https[:]//www[.]mediafire[.]com/file/edipk9kfgg35yfv/file
https[:]//www[.]mediafire[.]com/file/w484z24ykmu4ij7/file
https[:]//www[.]mediafire[.]com/file/uugv8bgqqgf98mq/file
https[:]//www[.]mediafire[.]com/file/6hoxo2x0qq5rez7/file
https[:]//www[.]mediafire[.]com/file/e5zk67dyxf3wpuy/file
https[:]//www[.]mediafire[.]com/file/bqgnkg396kosngf/file
https[:]//www[.]mediafire[.]com/file/nali61e33jqvej0/file
https[:]//www[.]mediafire[.]com/file/kyagfeqccz1dxv1/file
https[:]//www[.]mediafire[.]com/file/o7pqqbv5lhfvx0o/file
https[:]//www[.]mediafire[.]com/file/ovanej3o1qm4eya/file
https[:]//www[.]mediafire[.]com/file/rmsaeapbsc6c299/file
https[:]//www[.]mediafire[.]com/file/s9f7eyr431bsj15/file
https[:]//www[.]mediafire[.]com/file/d811gm71t6e3kjj/file

# DOMAINS (Used in the download chain)
serverptsystem[.]top  # registered on Oct 05, 2026
btnewptweb[.]top  # registered on Oct 16, 2026
sixwebgetwork[.]top  # registered on Oct 16, 2026
yntjux[.]com  # registered on Oct 06, 2026
impdocw[.]com  # registered on Oct 15, 2026
jhsnhw[.]com  # registered on Oct 20, 2026
aytnmw[.]com  # registered on Oct 22, 2026
jntuxd[.]com  # registered on Oct 24, 2026
kztxw[.]com  # registered on Oct 21, 2026

# DOMAINS (Third level domains used for the second stage)
dry[.]access[.]ly
jueves[.]unusualperson[.]com
strongwoman[.]nhlfan[.]net
b45154456174400fd7[.]nhlfan[.]net
ab41vc541fd04435740[.]health-carereform[.]com
november[.]read-books[.]org
juliet[.]quicksytes[.]com
charlie[.]stufftoread[.]com
lima[.]collegefan[.]org
dont[.]servehumour[.]com

# DOMAINS (Observed active DGA)
qohflbwetjdvaguci[.]homesecuritymac[.]com
kqynhgmcpfoxitldberjzu[.]dnsfor[.]me
desyqwjluhvfigxnbcpkm[.]servesarcasm[.]com
pyglmnhsazxwcr[.]homesecuritypc[.]com
srtpomeujnyqd[.]hopto[.]me

# DOMAINS (Calculated DGAs for next days)
gxonlrycqdwpabfvhiszek[.]is-a-chef[.]net # 2026-10-30 candidate_1
qohflbwetjdvaguci[.]homesecuritymac[.]com # 2026-10-30 candidate_2
znrgtsxyhdkqwm[.]mywire[.]org # 2026-10-30 candidate_3
lhreqobujsivzftaxkydmnp[.]is-a-bruinsfan[.]org # 2026-10-31 candidate_1
ldfmsvucxhbgakotiw[.]mlbfan[.]org # 2026-10-31 candidate_2
mdekqfhvpgcoijwzylxsta[.]dynuddns[.]net # 2026-10-31 candidate_3
tqflcasvzbkrmhj[.]is-a-rockstar[.]com # 2026-11-01 candidate_1
hgsmnuxfpbdlikjrztvw[.]read-books[.]org # 2026-11-01 candidate_2
qbirzjetgswyhndvx[.]casacam[.]net # 2026-11-01 candidate_3
rkilhdqbxsujztowmypecf[.]from-ks[.]com # 2026-11-02 candidate_1
oubwetpcmjnfiazlqgvdx[.]pointto[.]us # 2026-11-02 candidate_2
xsuegjnzqlvwrdbyoh[.]ooguy[.]com # 2026-11-02 candidate_3
fnjuyhogblapevwtmczdkiq[.]from-ga[.]com # 2026-11-03 candidate_1
punqcoasidefblt[.]mmafan[.]biz # 2026-11-03 candidate_2
dnlupsfkzcij[.]mysynology[.]net # 2026-11-03 candidate_3
tebrwojuvgldsfxqcn[.]from-il[.]com # 2026-11-04 candidate_1
yxoeihqcdknsurza[.]ddns[.]me # 2026-11-04 candidate_2
pyvitwlkfagumo[.]camdvr[.]org # 2026-11-04 candidate_3
futhxvygmezwsjaicpn[.]scrapper-site[.]net # 2026-11-05 candidate_1
khijuzbdcvswgxtqomfanepr[.]blogsyte[.]com # 2026-11-05 candidate_2
zgscrivwelodfujqmykxb[.]ddnsguru[.]com # 2026-11-05 candidate_3
qmoztyuplvekc[.]mine[.]nu # 2026-11-06 candidate_1
jxmukvwzldog[.]stufftoread[.]com # 2026-11-06 candidate_2
aqwbunztirokefhclpmyjx[.]webredirect[.]org # 2026-11-06 candidate_3
volqymhzsgbwcr[.]homeunix[.]com # 2026-11-07 candidate_1
zaomtfuxwkrhlnpdegbi[.]cable-modem[.]org # 2026-11-07 candidate_2
tejdanuhwsyovxmbc[.]ddnsfree[.]com # 2026-11-07 candidate_3
crwkegapzolfnhjyqdbxtm[.]homedns[.]org # 2026-11-08 candidate_1
zwxouydmgsjhek[.]dynns[.]com # 2026-11-08 candidate_2
glmftshbwqvkxndpjayuecio[.]dynuddns[.]com # 2026-11-08 candidate_3
zpgbwsymudifavtlx[.]is-slick[.]com # 2026-11-09 candidate_1
ejofamkctszrung[.]ilovecollege[.]info # 2026-11-09 candidate_2
wiuepsyqnhov[.]kozow[.]com # 2026-11-09 candidate_3
oyinefjkcpglaxwbvs[.]dyndns-at-work[.]com # 2026-11-10 candidate_1
topzgredaqycxklhumvfbis[.]mysecuritycamera[.]org # 2026-11-10 candidate_2
oehbklvuwadyirgfzsnm[.]theworkpc[.]com # 2026-11-10 candidate_3

# IP ADDRESSES
104[.]21[.]7[.]185 # resolved from serverptsystem[.]top
45[.]61[.]139[.]230 # resolved from btnewptweb[.]top
89[.]117[.]63[.]187 # resolved from sixwebgetwork[.]top
89[.]117[.]54[.]210 # resolved from yntjux[.]com
89[.]117[.]54[.]210 # resolved from impdocw[.]com
109[.]123[.]242[.]187 # resolved from jhsnhw[.]com
84[.]46[.]255[.]149 # resolved from aytnmw[.]com
84[.]247[.]178[.]210 # resolved from jntuxd[.]com
194[.]195[.]87[.]23 # resolved from kztxw[.]com
54[.]198[.]109[.]141 # resolved from 3rd level domains
204[.]236[.]194[.]253 # resolved from 3rd level domains
54[.]227[.]90[.]222 # resolved from 3rd level domains
104[.]131[.]68[.]180 # resolved from 3rd level domains
3[.]80[.]80[.]137 # resolved from 3rd level domains
15[.]224[.]208[.]8 # resolved from DGA domains
```
