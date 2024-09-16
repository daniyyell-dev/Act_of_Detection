rule Detect_Remcos_RAT {
    meta:
        author = "daniyyell"
        date = "2024-09-10"
        description = "Detects Remcos RAT payloads and commands"
        yarahub_uuid = "1173ea90-e68d-4412-8348-44430b9e1ff5"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "65363c1147fb7a4c3e42de314a5b002e"
        malpedia_family = "win.remcos"
        aka = "Remcos RAT"

    strings:
        $ps_command = /powershell\.exe\s+-windowstyle\s+hidden\s+-executionpolicy\s+bypass\s+-NoProfile\s+-command\s+"\$imageUrl\s+=\s+'https:\/\/[a-zA-Z0-9\.\/]+'\;\$webClient\s+=\s+New-Object\s+System\.Net\.WebClient\;\$imageBytes\s+=\s+\$webClient\.DownloadData\(\$imageUrl\)\;\$imageText\s+=\s+\[System\.Text\.Encoding\]::UTF8\.GetString\(\$imageBytes\)\;\$startFlag\s+=\s+'<<BASE64_START>>'\;\$endFlag\s+=\s+'<<BASE64_END>>'\;\$startIndex\s+=\s+\$imageText\.IndexOf\(\$startFlag\)\;\$endIndex\s+=\s+\$imageText\.IndexOf\(\$endFlag\)\;\$startIndex\s+-ge\s+0\s+-and\s+\$endIndex\s+-gt\s+\$startIndex\;\$startIndex\s+\+=\s+\$startFlag\.Length\;\$base64Length\s+=\s+\$endIndex\s+-\s+\$startIndex\;\$base64Command\s+=\s+\$imageText\.Substring\(\$startIndex\,\s+\$base64Length\)\;\$commandBytes\s+=\s+\[System\.Convert\]::FromBase64String\(\$base64Command\)\;\$loadedAssembly\s+=\s+\[System\.Reflection\.Assembly\]::Load\(\$commandBytes\)\;\$type\s+=\s+\$loadedAssembly\.GetType\('dnlib\.IO\.Home'\)\;\$method\s+=\s+\$type\.GetMethod\('VAI'\)\.Invoke\(\$null\,\s+\[object\[\]\]\s+\('txt\.wed\/yrcbv\/ue\.rellorhsupws\.sab\/\/:ptth'\,\s+'1'\,\s+'C:\\ProgramData\\'\,\s+'amyloforme'\,\s+'aspnet_compiler'\,\s+'desativado'\)\)/

        $eqnedit = /"C:\\Program Files\\Common Files\\Microsoft Shared\\EQUATION\\EQNEDT32\.EXE"\s+-Embedding/
        $base64_start = /<<BASE64_START>>/
        $base64_end = /<<BASE64_END>>/
        $powershell_path = /C:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe/
        $file_path = /C:\\ProgramData\\remcos\\logs\.dat/
        $webclient = /New-Object\s+System\.Net\.WebClient/
        $encoding = /\[System\.Text\.Encoding\]::UTF8\.GetString\(\$imageBytes\)/

    condition:
        any of ($ps_command, $eqnedit, $base64_start, $base64_end, $powershell_path, $file_path, $webclient, $encoding)
}
