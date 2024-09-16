rule detect_tiny_vbs {
    meta:
        author = "daniyyell"
        date = "2024-09-02"
        description = "Detects tiny VBS delivery technique"
        yarahub_uuid = "41a2ebcf-dcf9-45c5-ad80-c3348249009d"  // UUID in lowercase
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "acfa481a369f1e796756532822ee40b2"
        malpedia_family = "win.kimsuky"
        aka = "vbs"

    strings:
        $dim = "Dim" nocase
        $wscript_shell = "Wscript.Shell" nocase
        $end_function = "End Function" nocase
        $create_object = "CreateObject" nocase

    condition:
        all of them
}
