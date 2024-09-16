rule Detect_PowerShell_Techniques {
    meta:
        author = "daniyyell"
        date = "2024-09-10"
        description = "Detects sophisticated PowerShell commands and techniques used by APTs."
        yarahub_uuid = "4d3fb05d-64a3-4b74-b2e1-5fee9de448b2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "65363c1147fb7a4c3e42de314a5b002e"
        malpedia_family = "win.remcos"
        aka = "Remcos RAT"

    strings:
        $execution_policy_bypass = /powershell\s+-executionpolicy\s+bypass\s+-file\s+\S+/i
        $certutil_download = /certutil\s+-urlcache\s+-f\s+http:\/\/\S+\/\S+\s+\S+/i
        $invoke_expression_webclient = /invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)/i
        $scheduled_task = /schtasks\s+\/create\s+\/tn\s+"\S+"\s+\/tr\s+"powershell\s+-executionpolicy\s+bypass\s+-file\s+\S+"\s+\/sc\s+daily\s+\/st\s+\d{2}:\d{2}/i
        $profile_modification = /add-content\s+\$profile\s+"invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)"/i
        $data_exfiltration = /invoke-webrequest\s+-uri\s+http:\/\/\S+\/upload\s+-method\s+post\s+-body\s+\$data/i
        $hidden_mode = /start-process\s+powershell\s+-argumentlist\s+'-nop\s+-w\s+hidden\s+-c\s+"invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)"'/i
        $file_download_execution = /powershell\s+-nop\s+-w\s+hidden\s+-c\s+"\$client\s+=\s+new-object\s+system\.net\.webclient;\s+\$client\.downloadfile\('http:\/\/\S+\/\S+'\s+,\s+'c:\\\S+'\)"/i
        $self_destructing_script = /$script\s+=\s+"invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)";\s+\$tempfile\s+=\s+\[system\.io\.path\]::gettempfilename\(\);\s+\[system\.io\.file\]::writealltext\(\$tempfile,\s+\$script\);\s+start-process\s+powershell\s+-argumentlist\s+"-executionpolicy\s+bypass\s+-file\s+\$tempfile";\s+remove-item\s+\$tempfile/i
        $abusing_modules = /import-module\s+c:\\\path\\\to\\\maliciousmodule\.psm1/i
        $start_job = /start-job\s+-scriptblock\s+{invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)}/i
        $wmi_manipulation = /invoke-wmimethod\s+-class\s+win32_process\s+-name\s+create\s+-argumentlist\s+"powershell\.exe\s+-executionpolicy\s+bypass\s+-file\s+c:\\\path\\\to\\\script\.ps1"/i
        $dotnet_reflection = /\[system\.reflection\.assembly\]::load\(\[system\.text\.encoding\]::utf8\.getstring\(\[system\.convert\]::frombase64string\('base64string'\)\)\)/i
        $system_api_calls = /add-type\s+-typedefinition\s+"@{[^}]+}"/i
        $wsh_abuse = /\$wsh\s+=\s+new-object\s+-comobject\s+wscript\.shell\s+;\s+\$wsh\.run\("wscript\.exe\s+c:\\\path\\\to\\\malicious\.vbs"\)/i
        $alternate_data_streams = /add-content\s+-path\s+"c:\\\path\\\to\\\file\.txt"\s+-value\s+"malicious\s+code"\s+-stream\s+"alternatedatastream"/i
        $remoting = /enter-pssession\s+-computername\s+targetmachine\s+-credential\s+\(get-credential\)/i
        $runspace = /\$runspace\s+=\s+\[powershell\]::create\(\)\.addscript\("invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)"\)\s+\$runspace\.begininvoke\(\)/i
        $env_vars = /\[environment\]::setenvironmentvariable\("maliciousscript",\s+"powershell\s+-executionpolicy\s+bypass\s+-file\s+c:\\\path\\\to\\\script\.ps1",\s+\[environmentvariabletarget\]::machine\)/i
        $profile_hijacking = /\$profilepath\s+=\s+\[system\.io\.path\]::combine\(\$env:USERPROFILE,\s+"documents\\\windowspowershell\\\profile\.ps1"\)\s+;\s+add-content\s+\$profilepath\s+"invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)"/i
        $scriptblock_abuse = /\$sb\s+=\s+\[scriptblock\]::create\("invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)"\)\s+\&\$sb/i
        $powerhsell_jobs = /start-job\s+-scriptblock\s+{invoke-expression\s+\(new-object\s+net\.webclient\)\.downloadstring\('http:\/\/\S+'\)}/i
        $dynamic_assembly_loading = /\[system\.reflection\.assembly\]::load\(\[system\.convert\]::frombase64string\('base64string'\)\)/i
        $env_var_execution = /\[environment\]::setenvironmentvariable\("maliciousvar",\s+"powershell\s+-executionpolicy\s+bypass\s+-file\s+c:\\\path\\\to\\\script\.ps1",\s+\[environmentvariabletarget\]::user\)/i

    condition:
        any of ($execution_policy_bypass, $certutil_download, $invoke_expression_webclient, $scheduled_task, $profile_modification, $data_exfiltration, $hidden_mode, $file_download_execution, $self_destructing_script, $abusing_modules, $start_job, $wmi_manipulation, $dotnet_reflection, $system_api_calls, $wsh_abuse, $alternate_data_streams, $remoting, $runspace, $env_vars, $profile_hijacking, $scriptblock_abuse, $powerhsell_jobs, $dynamic_assembly_loading, $env_var_execution)
}
