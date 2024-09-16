rule Detect_APT29_WINELOADER_Backdoor {
    meta:
        author = "daniyyell"
        date = "2024-09-02"
        description = "Detects APT29's WINELOADER backdoor variant used in phishing campaigns, this rule also detect bad pdf,shtml,htm and vbs or maybe more depends"
        yarahub_uuid = "68e3a223-2495-4bc6-8eb6-845ae4164282"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "efafcd00b9157b4146506bd381326f39"
        malpedia_family = "win.wineloader"
        aka = "APT29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties"


    strings:
        $activex_wscript = /new\s+ActiveXObject\("Wscript\.Shell"\)/
        $activex_filesystem = /new\s+ActiveXObject\("Scripting\.FileSystemObject"\)/
        $http_request = /new\s+XMLHttpRequest\(\);/
        $certutil_decode = /certutil\s+-decode\s+C:\\Windows\\Tasks\\[^\s]+\s+C:\\Windows\\Tasks\\[^\s]+/
        $tar_extract = /tar\s+-xf\s+C:\\Windows\\Tasks\\[^\s]+\s+-C\s+C:\\Windows\\Tasks\\/
        $sqli_dumper = /C:\\Windows\\Tasks\\SqlDumper\.exe/
        $url_pattern = /https?:\/\/[a-zA-Z0-9\.-]+[\/\w\.-]*/  // Regular expression to match any URL
        
    condition:
        any of ($activex_wscript, $activex_filesystem, $http_request, $certutil_decode, $tar_extract, $sqli_dumper, $url_pattern)
}
