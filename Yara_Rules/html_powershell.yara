rule detect_captcha_and_Reverse_Shell {
    meta:
        author = "daniyyell"
        date = "2024-09-16"
        description = "Detects PowerShell reverse shell behaviour and web-based reverse shell downloads on Windows"
        yarahub_uuid = "4C5375A1-0568-49DA-9849-DB072189E9FC"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "acfa481a369f1e796756532822ee40b2"
        malpedia_family = "win.remcos"
        aka = "PowerShell reverse shell and downloader script detection"
    
    strings:
        // Identifying key parts of the reverse shell code
        $ps_tcpclient = "New-Object System.Net.Sockets.TcpClient" 
        $ps_stream = "$stream = $client.GetStream()"
        $ps_buffer = "[byte[]]$buffer = 0..65535"
        $ps_read = "$i = $stream.Read($buffer, 0, $buffer.Length)"
        $ps_iex = "(iex $data 2>&1 | Out-String)"
        $ps_encoding = "([text.encoding]::UTF8).GetBytes"
        $ps_close = "$client.Close()"

        // Identifying PowerShell reverse shell via WebClient download
        $ps_webclient = "New-Object Net.WebClient"
        $ps_downloadstring = ".DownloadString"

        // Common PowerShell arguments used for obfuscation
        $ps_obfuscation = "-NoP -NonI -W Hidden -Exec Bypass"

        // Variations for potential obfuscation or formatting differences
        $ps_tcpclient_regex = /New-Object\s+System\.Net\.Sockets\.TcpClient/i
        $ps_iex_regex = /\(iex\s+\$data\s+2>&1\s+\|\s+Out-String\)/i
        $ps_encoding_regex = /\[text\.encoding\]::UTF8\.GetBytes/i
        $ps_webclient_regex = /New-Object\s+Net\.WebClient/i
        $ps_downloadstring_regex = /\.DownloadString/i
        $ps_obfuscation_regex = /-NoP\s+-NonI\s+-W\s+Hidden\s+-Exec\s+Bypass/i

    condition:
        // Matches reverse shell or web downloader components
        all of ($ps_tcpclient, $ps_stream, $ps_buffer, $ps_read, $ps_iex, $ps_encoding, $ps_close) or
        (all of ($ps_tcpclient_regex, $ps_iex_regex, $ps_encoding_regex)) or
        all of ($ps_webclient, $ps_downloadstring, $ps_obfuscation) or
        (all of ($ps_webclient_regex, $ps_downloadstring_regex, $ps_obfuscation_regex))
}
