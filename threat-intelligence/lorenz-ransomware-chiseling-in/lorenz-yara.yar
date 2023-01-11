rule webshell_php_3b64command: Webshells PHP B64 {
  meta:
    Description= "Detects Possible PHP Webshell expecting triple base64 command"
    Category = "Malware"
    Author = "Arctic Wolf Labs"
    Date = "2022-09-12"
    Hash = "07838ac8fd5a59bb741aae0cf3abf48296677be7ac0864c4f124c2e168c0af94"
    Reference = "https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in"
  strings:
    $decode = "base64_decode(base64_decode(base64_decode(" ascii
    $encode = "base64_encode(base64_encode(base64_encode(" ascii
    $s1 = "popen(" ascii
    $s2 = "pclose" ascii
    $s3 = "fread(" ascii
    $s4 = "$_POST" ascii
  condition:
    $decode and $encode
    and 3 of ($s*)
    and filesize < 2KB
}

rule webshell_php_simple: Webshells PHP Simple {
  meta:
    Description = "A simpler version of the webshells, observed by forensic examiners at S-RM, accessed by Lorenz deploying Hive Ransomware"
    Category = "Malware"
    Author = "Arctic Wolf Labs"
    Date = "2023-01-10"
    Reference = "https://insights.s-rminform.com/lorenz-cyber-intelligence-briefing-special"
  strings:
    $if_id = "if($_POST["id"]"
    $eval_img = "eval($_POST["img"]"
  condition:
    $if_id and $eval_img
}

rule hktl_chisel_artifacts: Chisel Hacktool Artifacts {
  meta:
    Description = "looks for hacktool chisel artifacts potentially left in memory or unallocated space"
    Category = "Tool"
    Author = "Arctic Wolf Labs"
    Date = "2022-09-12"
    Reference = "https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in"
  strings:
    $chisel = "chisel_1." ascii
    $s1 = "client" ascii
    $s2 = "--tls-skip-verify" ascii
    $s3 = "--fingerprint" ascii
    $s4 = "R:socks" ascii
  condition:
    $chisel or 3 of ($s*)
}
