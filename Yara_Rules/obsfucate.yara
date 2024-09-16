rule Detect_PowerShell_Obfuscation {
    meta:
        author = "daniyyell"
        date = "2024-09-02"
        description = "Detects obfuscated PowerShell commands commonly used in malicious scripts."
        yarahub_uuid = "68a95493-902a-42c4-8fce-79aae49f664d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "6b887615fcf52557c91de9929903d93b"
        malpedia_family = "win.coreshell"
        aka = "APT28"

    strings:
        // Detect encoded PowerShell command
        $powershell_encoded = /powershe[lL] -e/
        // Detect common obfuscated PowerShell patterns
        $obf_new_item = /new-i?tem/i
        $obf_webclient = /new-object net.webclient/i
        $obf_download_file = /downloadfile/i
        $obf_invoke_item = /invoke-item/i

    condition:
        $powershell_encoded or any of ($obf_new_item, $obf_webclient, $obf_download_file, $obf_invoke_item)
}
