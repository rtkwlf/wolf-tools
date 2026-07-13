rule BoryptGrab_infostealer {
    meta:
        description = "Rule to detect BoryptGrab infostealer used in GitHub case"
        author = "Arctic Wolf"
        distribution = "TLP:CLEAR"
        version = "1.0"
        last_modified = "2026-07-02"
        sha256 = "e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2"
    strings:
        $a1 = "locked, killing browser processes" ascii wide
        $a2 = "CopyBrowserData: [OK] extensions.json" ascii wide
        $a3 = "CopyBrowserData: [LOCKED]" ascii wide
        $a4 = "CopyTelegramData: Copying" ascii wide
        $a5 = "Found %d user(s), processing %d wallet rules" ascii wide
        $a6 = "GetBrowserMasterKey: SUCCESS, master key extracted:" ascii wide
        $a7 = "ExtractDiscordTokens: Saved %d unique token(s) to Discord_tokens.txt" ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and (all of ($a*))
}