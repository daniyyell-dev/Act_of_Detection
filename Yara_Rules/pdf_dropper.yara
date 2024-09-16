rule Detect_Malicious_PDF_Dropper
{
    meta:
        author = "daniyyell"
        yarahub_author_twitter = "@dani_yyell"
        date = "2024-08-30"
        description = "Detects a malicious PDF dropper that uses specific objects and patterns indicative of malware activity."
        yarahub_uuid = "cc553ae6-2565-41be-8449-dcc1b7485154"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:RED"
        yarahub_reference_md5 = "fca79bd416cb1cf2a9d16884aa9742d9"
        malpedia_family = "win.cloudeye"
        aka = "PDF Exploit or PDF Dropper"

    strings:
        // PDF header and common object patterns
        $pdf_header = "%PDF-1.3"
        $catalog_obj = "/Type /Catalog"
        $pages_obj = "/Type /Pages"
        $page_obj = "/Type /Page"
        $flate_decode = "/Filter /FlateDecode"

        // Potential malicious patterns in the PDF content
        $cmd_chrome = "cmd.exe /c start chrome.exe"
        $launch_action = "/S /Launch"
        $obfuscated_command = "/JavaScript << /JS (this.exportDataObject)"
        $anonymous_author = "/Author (anonymous)"

    condition:
        // The PDF header must be present along with any malicious indicators or specific objects
        $pdf_header and 
        (all of ($catalog_obj, $pages_obj, $page_obj, $flate_decode) and
        any of ($cmd_chrome, $launch_action, $obfuscated_command, $anonymous_author))
}
