rule detect_STRRAT_javascripts_Malware {
            meta:
                author = "daniyyell"
                date = "2024-10-05"
                description = "Detects obfuscated JavaScript code indicative of STRRAT malware."
                yarahub_uuid = "57772A73-3272-43A3-AC04-B47ADF2442B4"
                yarahub_license = "CC0 1.0"
                yarahub_rule_matching_tlp = "TLP:WHITE"
                yarahub_rule_sharing_tlp = "TLP:WHITE"
                yarahub_reference_md5 = "ec7b21746a03ffd34199f1943b74fe5e"
                malpedia_family = "jar.strrat"
                aka = "STRRAT Malware"

            strings:
                // Key function patterns associated with obfuscated JavaScript
                $str_eval = "eval("
                $str_prototype = "String[\"prototype\"]"
                $str_proc = "proc = function() { eval(this.toString());};"
                $str_undefined = "String[\"prototype\"][\"\\x75\\x6E\\x64\\x65\\x66\\x69\\x6E\\x65\\x64\"] = function(xx, xy) {"
                $str_array_replace = "Array.prototype.om0l4d3 = function() {"
                $str_mp3_function = ".mp3;"
                
                // Regex to capture the obfuscated patterns
                $obfuscated_str1 = /String\["prototype"\]\.proc\s*=\s*function\(\)\s*{\s*eval\(this\.toString\(\)\);\s*}/
                $obfuscated_str2 = /String\["prototype"\]\["\\x75\\x6E\\x64\\x65\\x66\\x69\\x6E\\x65\\x64"\]\s*=\s*function\(xx,\s*xy\)\s*{/
                $obfuscated_str3 = /var\s+exp\s*=\s*\/{(\d+)}/ 
                $obfuscated_str5 = /this\.toString\(\).length/

            condition:
                // At least one of the key strings and one of the obfuscated patterns must be present
                any of ($str_eval, $str_prototype, $str_proc, $str_undefined, $str_array_replace, $str_mp3_function) and
                any of ($obfuscated_str1, $obfuscated_str2, $obfuscated_str3, $obfuscated_str5)
        }
