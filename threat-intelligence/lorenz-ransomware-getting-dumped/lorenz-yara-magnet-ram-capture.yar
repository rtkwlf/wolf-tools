import "pe"

rule tool_memdump_magnet_ram_capture {

    meta:
        description = "Detects legitimate signed Magnet RAM Capture which uses a kernel-mode driver to acquire RAM"
        author = "Arctic Wolf Labs"
        date = "2023-01-26"
        category = "Tool"   
        actor = "Lorenz Ransomware Group"
	reference = "https://arcticwolf.com/resources/blog/lorenz-ransomware-getting-dumped"
        hash1 = "72dc1ba6ddc9d572d70a194ebdf6027039734ecee23a02751b0b3b3c4ea430de"

    condition:

        uint16(0) == 0x5a4d
        and filesize < 400KB 
        and pe.version_info["FileDescription"] contains "Magnet RAM Capture"
        and pe.version_info["ProductName"] contains "Magnet RAM Capture"
        and pe.version_info["CompanyName"] contains "Magnet Forensics Inc."
                 
}


rule driver_memdump_magnet_ram_capture {

    meta:
        description = "Detects kernel-mode driver used in  Magnet RAM Capture"
        author = "Arctic Wolf Labs"
        date = "2023-01-26"
        category = "Driver"   
        actor = "Lorenz Ransomware Group"
	reference = "https://arcticwolf.com/resources/blog/lorenz-ransomware-getting-dumped"
        hash1 = "C0CAFFD00B9576725ACF9DBE15AF8FC64EA000CB527F1FBCAA3CBDCF52C99152"
        hash2 = "5FFF657939E757922941162376ADB86B7A37DC329A1F9969C70F23E7D54B7B4C"
        hash3 = "3766619B7564F84185CF8CC952EE5513C45C6D858EF971C5FD1B0BDF234B8BAA"
        hash4 = "654629028CF878126A25B8449B5F1AC4D828B5ADC03BB393062D46415A78F39B"

    condition:

        uint16(0) == 0x5a4d
        and filesize < 30KB
	and 
        (
            (
                pe.version_info["FileDescription"] == "MagnetRAMCapture Driver"
                and 
                pe.version_info["OriginalFilename"] == "MagnetRAMCapture.sys"
                and 
                ( 
                    pe.pdb_path == "C:\\magnetdev\\tools\\tool-magnet-ramcapture\\ramdriver\\x64\\Release\\ramdriver.pdb"
                    or
                    pe.pdb_path == "C:\\magnetdev\\tools\\tool-magnet-ramcapture\\ramdriver\\Release\\ramdriver.pdb"
                )

            )
            or 
            (
                pe.version_info["FileDescription"] == "IefRamDump Driver"
                and 
                pe.version_info["OriginalFilename"] == "ieframdump.sys"
                and 
                ( 
                   
                    pe.pdb_path == "d:\\projects\\ramreader\\driver\\sys\\i386\\ieframdump.pdb"
                    or
                    pe.pdb_path == "d:\\projects\\ramreader\\driver\\sys\\amd64\\ieframdump.pdb"
                )
            )
           
        )
                 
}
