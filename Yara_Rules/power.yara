rule detect_powershell {
    meta:
        author = "daniyyell"
        date = "2024-09-12"
        description = "Detects suspicious PowerShell activity related to malware execution"
        yarahub_uuid = "0b6445e8-9c0e-4030-ae33-412d223eae62"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "cd7870e220fad26aae6ae1d03fa354b8"
        malpedia_family = "win.remcos"
        aka = "powershell"

    strings:
        $cmd1 = "New-Object" ascii wide
        $cmd2 = "[convert]::ToInt32" ascii wide
        $cmd3 = "Get-Random" ascii wide
        $cmd4 = "Get-WmiObject" ascii wide
        $cmd5 = "[System.IO.File]::Exists" ascii wide
        $cmd6 = "Out-File" ascii wide
        $cmd7 = "Write-Host" ascii wide
        $cmd8 = "Set-Content" ascii wide
        $cmd9 = "New-Item" ascii wide
        $cmd10 = "Remove-Item" ascii wide
        $cmd11 = "Test-Path" ascii wide
        $cmd12 = "Start-Process" ascii wide
        $cmd13 = "ForEach-Object" ascii wide
        $cmd14 = "Sort-Object" ascii wide
        $cmd15 = "Where-Object" ascii wide
        $cmd16 = "Start-Sleep" ascii wide
        $cmd17 = "[System.DateTime]::Now" ascii wide
        $cmd18 = "[System.IO.Path]::GetFileNameWithoutExtension" ascii wide
        $cmd19 = "New-Object -com shell.application" ascii wide
        $cmd20 = "Invoke-WebRequest" ascii wide
        $cmd21 = "Invoke-Expression" ascii wide
        $cmd22 = "Invoke-Command" ascii wide
        $cmd23 = "Start-Job" ascii wide
        $cmd24 = "Invoke-RestMethod" ascii wide
        $cmd25 = "Start-Transcript" ascii wide
        $cmd26 = "Get-Process" ascii wide
        $cmd27 = "Stop-Process" ascii wide
        $cmd28 = "Get-Service" ascii wide
        $cmd29 = "Start-Service" ascii wide
        $cmd30 = "Stop-Service" ascii wide
        $cmd31 = "New-Service" ascii wide
        $cmd32 = "Invoke-WmiMethod" ascii wide
        $cmd33 = "Add-Type" ascii wide
        $cmd34 = "Set-ExecutionPolicy Bypass" ascii wide
        $cmd35 = "Unblock-File" ascii wide
        $cmd36 = "[ScriptBlock]::Create()" ascii wide
        $cmd37 = "[System.Reflection.Assembly]::Load" ascii wide
        $cmd38 = "Get-Credential" ascii wide

        $ps_random_function = /function\s+vS35wIDY9U/ nocase
        $ps_decrypt_function = /function\s+wEAXbwCuxi/ nocase
        $ps_webclient = /New-Object\s+System\.Net\.WebClient/ nocase
        $ps_downloadstring = /DownloadString/ nocase
        $ps_tcpclient = /New-Object\s+System\.Net\.Sockets\.TcpClient/ nocase
        $ps_getwmiobject = /Get-WmiObject/ nocase
        $ps_write_host_ok = /Write-Host\s+"ok"/ nocase
        $ps_write_host_no = /Write-Host\s+"no"/ nocase
        $ps_invoke_expression = /IEX\s+/ nocase
        $ps_invoke_command = /Invoke-Command/ nocase
        $ps_start_job = /Start-Job/ nocase
        $ps_unblock_file = /Unblock-File/ nocase
        $ps_set_execution_policy = /Set-ExecutionPolicy\s+Bypass/ nocase
        $ps_add_type = /Add-Type/ nocase
        $ps_reflection_load = /[System\.Reflection\.Assembly]::Load/ nocase

    condition:
        3 of ($cmd*, $ps_random_function, $ps_decrypt_function, $ps_webclient, $ps_downloadstring, $ps_tcpclient, $ps_getwmiobject, $ps_write_host_ok, $ps_write_host_no, $ps_invoke_expression, $ps_invoke_command, $ps_start_job, $ps_unblock_file, $ps_set_execution_policy, $ps_add_type, $ps_reflection_load)
}
