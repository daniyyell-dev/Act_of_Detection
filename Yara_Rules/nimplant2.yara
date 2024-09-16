rule Detect_Nimplant_PE
{
    meta:
        author = "daniyyell"
        yarahub_author_twitter = "@dani_yyell"
        date = "2024-08-30"
        description = "Detects malicious nimplant variant PE malware."
        yarahub_uuid = "4880505a-4f04-41b2-b65c-061526a382d9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "dd0210ee58c682c90c6162ed9d6a4dea"
        malpedia_family = "win.nimplant"
        aka = "Lightweight Nimplant C2"

    strings:
        // DLL and library names
        $bcrypt_dll = "Bcrypt.dll"
        $bcrypt_dll_alt = "Bcrypt.dil"
        $system_dll = "System.dil"
        $system_drawing_dll = "System.Drawing.dll"
        $ws2_32_dll = "Ws2_32.dil"
        $ws2_32_dll_alt = "Ws2_32.dli"
        $user32_dll = "USER32.dll"
        $msvcrt_dll = "msvcrt.dil"
        $kernel32_dll = "KERNEL32.dIl"

        // Malicious file names
        $pixle_nim = "pixle.nim"
        $urls_nim = "urls.nim"
        $gzip_nim = "gzip.nim"
        $base64_nim = "base64.nim"
        $zippy_nim = "zippy.nim"
        $deflate_nim = "deflate.nim"
        $platform_nim = "platform.nim"
        $fatal_nim = "fatal.nim"
        $deques_nim = "deques.nim"
        $parsetoml_nim = "parsetoml.nim"
        $png_nim = "png.nim"
        $json_nim = "json.nim"
        $com_nim = "com.nim"
        $inflate_nim = "inflate.nim"
        $syncio_nim = "syncio.nim"
        $clr_nim = "clr.nim"
        $puppy_nim = "puppy.nim"
        $times_nim = "times.nim"
        $tables_nim = "tables.nim"
        $queryparams_nim = "queryparams.nim"
        $adler32_simd_nim = "adler32_simd.nim"
        $strutils_nim = "strutils.nim"
        $options_nim = "options.nim"
        $bitstreams_nim = "bitstreams.nim"
        $winregistry_nim = "winregistry.nim"
        $qoi_nim = "qoi.nim"
        $parseutils_nim = "parseutils.nim"
        $parsejson_nim = "parsejson.nim"
        $osdirs_nim = "osdirs.nim"
        $system_nim = "system.nim"
        $winstr_nim = "winstr.nim"
        $oserrors_nim = "oserrors.nim"
        $common_nim = "common.nim"

        // Specific rdata strings
        $get_computer_name_w = { 47 65 74 43 6F 6D 70 75 74 65 72 4E 61 6D 65 57 }
        $create_process = { 53 65 6C 66 00 43 72 65 61 74 65 50 72 6F 63 75 72 72 65 65 73 6E 73 74 54 50 6F 6B 65 72 6F 63 6E 65 00 }
        $get_current_process_rdata = { 65 6E 65 74 50 43 72 6F 63 75 72 72 65 65 73 6E 73 74 54 50 6F 6B 65 72 6F 63 6E 65 00 }
        $get_user_name_w = { 47 65 74 55 73 65 72 4E 61 6D 65 57 }
        $open_process_token = { 6F 70 65 6E 50 72 6F 63 65 73 73 54 6F 6B 65 6E }
        $create_file_a = { 43 72 65 61 74 65 50 72 6F 63 65 73 73 }
        $virtual_protect = { 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }
        $create_toolhelp32 = { 43 72 65 61 74 65 54 6F 6F 6C 68 65 6C 70 33 32 }
        $connect_winhttp = { 43 6F 6E 6E 65 63 74 00 57 69 6E 48 74 74 70 }

        // Zlib references
        $zlib_pattern = { 38 43 7A 78 70 78 31 34 9C 78 93 01 00 00 00 01 00 80 43 38 7A 78 70 78 31 34 9C 78 93 01 00 00 00 01 00 }

        // TLS Callbacks
        $tls_callbacks_0 = { 14 00 09 AC E0 }
        $tls_callbacks_1 = { 14 00 09 AC B0 }

        // Additional Strings
        $uawavauatwvsh = "UAWAVAUATWVSH"
        $uavauatwvsh = "UAVAUATWVSH"
        $uwvsh = "UWVSH"
        $auuatwvsh = "UAUATWVSH"
        $hkey_dyn_data = "@HKEY_DYN_DATA"
        $hkey_current_config = "@HKEY_CURRENT_CONFIG"
        $hkey_performance_data = "@HKEY_PERFORMANCE_DATA"
        $hkey_users = "@HKEY_USERS"
        $hkey_local_machine = "@HKEY_LOCAL_MACHINE"
        $hkey_current_user = "@HKEY_CURRENT_USER"
        $hkey_classes_root = "@HKEY_CLASSES_ROOT"
        $nimplant_v1_4 = "@NimPlant v1.4"

        // Function patterns in hex
        $func1 = { 8B 44 DE 08 }
        $func2 = { 8B 44 DC 08 }

    condition:
        // Check for the presence of any of the specified strings or patterns
        any of ($bcrypt_dll, $bcrypt_dll_alt, $system_dll, $system_drawing_dll, $ws2_32_dll, $ws2_32_dll_alt, $pixle_nim, $urls_nim, $gzip_nim, $base64_nim, $zippy_nim, $deflate_nim, $platform_nim, $fatal_nim, $deques_nim, $parsetoml_nim, $png_nim, $json_nim, $com_nim, $inflate_nim, $syncio_nim, $clr_nim, $puppy_nim, $times_nim, $tables_nim, $queryparams_nim, $adler32_simd_nim, $strutils_nim, $options_nim, $bitstreams_nim, $winregistry_nim, $qoi_nim, $parseutils_nim, $parsejson_nim, $osdirs_nim, $system_nim, $winstr_nim, $oserrors_nim, $common_nim, $user32_dll, $msvcrt_dll, $kernel32_dll) or
        any of ($get_computer_name_w, $create_process, $get_current_process_rdata, $get_user_name_w, $open_process_token, $create_file_a, $virtual_protect, $create_toolhelp32, $connect_winhttp) or
        any of ($zlib_pattern) or
        any of ($tls_callbacks_0, $tls_callbacks_1) or // Include TLS Callbacks
        any of ($uawavauatwvsh, $uavauatwvsh, $uwvsh, $auuatwvsh, $hkey_dyn_data, $hkey_current_config, $hkey_performance_data, $hkey_users, $hkey_local_machine, $hkey_current_user, $hkey_classes_root, $nimplant_v1_4) or
        any of ($func1, $func2)
}
