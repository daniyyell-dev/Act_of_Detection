rule Detect_Malicious_VBScript_Base64
{
    meta:
        author = "daniyyell"
        yarahub_author_twitter = "@dani_yyell"
        date = "2024-08-30"
        description = "Detects malicious VBScript patterns, including Base64 decoding, file operations, and PowerShell."
        yarahub_uuid = "d4cd47a5-41e7-46f7-8bb7-929c48412af6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "fca79bd416cb1cf2a9d16884aa9742d9"
        malpedia_family = "vbs.cageychameleon"
        aka = "Cabbage RAT"

    strings:
        // Patterns to detect specific VBScript characteristics
        $func_pattern = "Function "
        $base64decode_pattern = "<B64DECODE xmlns:dt="
        $createobject_msxml = "CreateObject(\"MSXML2.DOMDocument.3.0\")"
        $createobject_fso = "CreateObject(\"Scripting.FileSystemObject\")"
        $createobject_ws = "CreateObject(\"Wscript.Shell\")"
        $special_folder = "GetSpecialFolder(2)"
        
        // Patterns to detect common malicious PowerShell usage
        $ps_nop = "powershell.exe -nop"
        $ps_hidden = "powershell.exe -w hidden"
        $ps_encoded_command = "-encodedcommand"
        $ps_exec = "Invoke-Expression"
        $ps_download = "IEX (New-Object Net.WebClient).DownloadString"
        $ps_base64 = "-e "
        $ps_bypass = "-ExecutionPolicy Bypass"
        $ps_unrestricted = "-ExecutionPolicy Unrestricted"
        $ps_hidden_window = "-WindowStyle Hidden"
        $ps_hidden_jobs = "Start-Job"
        $ps_reflection_assembly = "System.Reflection.Assembly"
        $ps_shell_open = "Start-Process powershell"
        $ps_fileless = "Invoke-Command"
        $ps_malicious_shortcut = "New-Object -ComObject WScript.Shell"
        $ps_obfuscation = "(('p'+'owe'+'rsh'+'ell')"

        // Additional VBScript patterns
        $vb_window_close = "window.close()"
        $vb_run = "*.Run"
        $vb_timer = "-4000"
        $vb_script_language = "<script language=\"VBScript\">"

    condition:
        any of ($func_pattern, $base64decode_pattern, $createobject_msxml, $createobject_fso, $createobject_ws, 
                $special_folder, $ps_nop, $ps_hidden, $ps_encoded_command, $ps_exec, $ps_download, 
                $ps_base64, $ps_bypass, $ps_unrestricted, $ps_hidden_window, $ps_hidden_jobs, 
                $ps_reflection_assembly, $ps_shell_open, $ps_fileless, $ps_malicious_shortcut, 
                $ps_obfuscation, $vb_window_close, $vb_run, $vb_timer, $vb_script_language)
}
