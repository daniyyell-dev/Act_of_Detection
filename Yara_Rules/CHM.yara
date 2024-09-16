rule CHM_File_Executes_JS_Via_PowerShell {
    meta:
        author = "daniyyell"
        yarahub_author_twitter = "@dani_yyell"
        date = "2024-09-02"
        description = "Detects a Microsoft Compiled HTML Help (CHM) file that executes embedded JavaScript to launch a messagebox via PowerShell"
        yarahub_uuid = "0399b09c-a44b-4521-b4f7-b4bf1f0e67eb"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "6b887615fcf52557c91de9929903d93b"
        malpedia_family = "win.lunchmoney"
        aka = "CHM_Javascripts_dropper"

    strings:
        $s1 = "/$WWAssociativeLinks/Property"
        $s2 = "/$WWKeywordLinks/"
        $s3 = "/$WWKeywordLinks/BTree"
        $s4 = "/$WWKeywordLinks/Data"
        $s5 = "/$WWKeywordLinks/Map"
        $s6 = "/$WWKeywordLinks/Property"
        $s11 = "::DataSpace/NameList"
        $s12 = "7<(::DataSpace/Storage/MSCompressed/Content"
        $s13 = ",::DataSpace/Storage/MSCompressed/ControlData"
        $s14 = ")::DataSpace/Storage/MSCompressed/SpanInfo"
        $s15 = "/::DataSpace/Storage/MSCompressed/Transform/List"
        $s16 = "&::_::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/"
        $s17 = "i::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable"
        $s18 = "This archive was not made by the MS HTML Help Workshop(r)(tm) program, but by Free Pascal's chm package 3.0.4."
        $s19 = "Compiled by CHMCmd 3.0.4"
        $s20 = "HHA Version 4.74.8702"

    condition:
        any of ($s*) 
}
