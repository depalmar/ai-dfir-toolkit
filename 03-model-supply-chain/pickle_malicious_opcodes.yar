/*
   YARA rules: Malicious Pickle Detection for AI/ML Model Files
   Author: Raymond DePalma (ai-dfir-detections)
   Date: 2026-04-15
   Reference: https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
              https://www.cve.org/CVERecord?id=CVE-2025-32444  (vLLM Mooncake CVSS 10.0)
              https://www.cve.org/CVERecord?id=CVE-2025-1550   (Keras Lambda RCE)
   ATLAS: AML.T0010.002, AML.T0011, AML.T0018

   Detects malicious pickle bytecode patterns commonly found in
   weaponized AI/ML model files (.pt, .pth, .bin, .pkl, .ckpt).

   Pickle opcodes of concern:
     - GLOBAL  (\x63 'c')  - imports a class/function (protocol 0/1/2 style)
     - STACK_GLOBAL (\x93) - protocol 4+ class lookup (used with SHORT_BINUNICODE)
     - REDUCE  (\x52 'R')  - calls function with args
     - SHORT_BINUNICODE (\x8c) - 1-byte-length-prefixed UTF-8 string

   Protocol 0/1/2 GLOBAL format:
     c<module>\n<n>\n      e.g. "cos\nsystem\n"

   Protocol 4+ STACK_GLOBAL format (default since Python 3.8):
     \x8c<len><module>\x8c<len><n>\x93
     e.g. \x8c\x02os\x8c\x06system\x93

   Apply to: .pt, .pth, .bin, .ckpt, .pkl, .pickle, .joblib, ZIP archives
*/

rule Pickle_Dangerous_Imports
{
    meta:
        description = "Pickle file imports dangerous modules (os, subprocess, etc.)"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0018"
        owasp       = "LLM03:2025"
        severity    = "high"

    strings:
        // Protocol 0/1/2: c<module>\n<n>\n
        $p2_os         = /cos\n(system|popen|exec[lv]p?e?|spawn[lv]p?e?)\n/
        $p2_subprocess = /csubprocess\n(Popen|call|run|check_output|getstatusoutput)\n/
        $p2_builtins   = /cbuiltins\n(eval|exec|compile|__import__)\n/
        $p2_socket     = /csocket\nsocket\n/
        $p2_pty        = /cpty\nspawn\n/
        $p2_pickle     = /cpickle\nloads\n/
        $p2_runpy      = /crunpy\n_run_module\n/
        $p2_codecs     = /ccodecs\n(decode|encode)\n/
        $p2_posix      = /c(posix|nt)\nsystem\n/
        $p2_webbrowser = /cwebbrowser\nopen\n/
        $p2_httpx      = /c(httpx|requests)\n(get|post)\n/

        // Protocol 4+: \x8c<len><module>\x8c<len><n>\x93
        $p4_os_system     = { 8C 02 6F 73 [0-1] 8C 06 73 79 73 74 65 6D [0-1] 93 }                          // os.system
        $p4_os_popen      = { 8C 02 6F 73 [0-1] 8C 05 70 6F 70 65 6E [0-1] 93 }                             // os.popen
        $p4_subprocess_p  = { 8C 0A 73 75 62 70 72 6F 63 65 73 73 [0-1] 8C 05 50 6F 70 65 6E [0-1] 93 }     // subprocess.Popen
        $p4_subprocess_c  = { 8C 0A 73 75 62 70 72 6F 63 65 73 73 [0-1] 8C 04 63 61 6C 6C [0-1] 93 }        // subprocess.call
        $p4_subprocess_r  = { 8C 0A 73 75 62 70 72 6F 63 65 73 73 [0-1] 8C 03 72 75 6E [0-1] 93 }           // subprocess.run
        $p4_builtins_eval = { 8C 08 62 75 69 6C 74 69 6E 73 [0-1] 8C 04 65 76 61 6C [0-1] 93 }              // builtins.eval
        $p4_builtins_exec = { 8C 08 62 75 69 6C 74 69 6E 73 [0-1] 8C 04 65 78 65 63 [0-1] 93 }              // builtins.exec
        $p4_builtins_imp  = { 8C 08 62 75 69 6C 74 69 6E 73 [0-1] 8C 0A 5F 5F 69 6D 70 6F 72 74 5F 5F [0-1] 93 } // builtins.__import__
        $p4_builtins_comp = { 8C 08 62 75 69 6C 74 69 6E 73 [0-1] 8C 07 63 6F 6D 70 69 6C 65 [0-1] 93 }     // builtins.compile
        $p4_builtins_print = { 8C 08 62 75 69 6C 74 69 6E 73 [0-1] 8C 05 70 72 69 6E 74 [0-1] 93 }          // builtins.print (test marker)
        $p4_socket        = { 8C 06 73 6F 63 6B 65 74 [0-1] 8C 06 73 6F 63 6B 65 74 [0-1] 93 }              // socket.socket
        $p4_pty_spawn     = { 8C 03 70 74 79 [0-1] 8C 05 73 70 61 77 6E [0-1] 93 }                          // pty.spawn
        $p4_codecs_dec    = { 8C 06 63 6F 64 65 63 73 [0-1] 8C 06 64 65 63 6F 64 65 [0-1] 93 }              // codecs.decode
        $p4_posix_system  = { 8C 05 70 6F 73 69 78 [0-1] 8C 06 73 79 73 74 65 6D [0-1] 93 }                 // posix.system
        $p4_runpy         = { 8C 05 72 75 6E 70 79 [0-1] 8C 0B 5F 72 75 6E 5F 6D 6F 64 75 6C 65 [0-1] 93 } // runpy._run_module

        // Marker: pickle PROTO opcode (versions 2-5)
        $pkl_proto = { 80 ( 02 | 03 | 04 | 05 ) }

    condition:
        $pkl_proto and (any of ($p2_*) or any of ($p4_*)) and filesize < 51200MB
}

rule Pickle_Reduce_With_Shell_Command
{
    meta:
        description = "Pickle REDUCE opcode invoking shell commands"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0018"
        severity    = "critical"

    strings:
        $pkl_proto = { 80 ( 02 | 03 | 04 | 05 ) }

        // Protocol 2 GLOBAL+REDUCE patterns
        $p2_reduce_1 = /cos\nsystem\n[\x00-\xff]{0,200}R/
        $p2_reduce_2 = /csubprocess\n(Popen|call|run)\n[\x00-\xff]{0,500}R/
        $p2_reduce_3 = /cbuiltins\n(exec|eval)\n[\x00-\xff]{0,500}R/

        // Protocol 4+ STACK_GLOBAL ... REDUCE
        $p4_reduce = { 93 [0-500] 52 }

        // Shell command indicators
        $sh_cmd_1 = "/bin/sh"
        $sh_cmd_2 = "/bin/bash"
        $sh_cmd_3 = "cmd.exe"
        $sh_cmd_4 = "powershell"
        $sh_cmd_5 = "curl http"
        $sh_cmd_6 = "wget http"
        $sh_cmd_7 = "bash -c"
        $sh_cmd_8 = "python -c"
        $sh_cmd_9 = "/dev/tcp/"

    condition:
        $pkl_proto and
        (any of ($p2_reduce_*) or $p4_reduce) and
        any of ($sh_cmd_*)
}

rule Pickle_Network_Exfiltration
{
    meta:
        description = "Pickle file containing network exfiltration code"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0086"
        severity    = "critical"

    strings:
        $pkl_proto = { 80 ( 02 | 03 | 04 | 05 ) }

        $p2_socket  = /csocket\nsocket\n/
        $p4_socket  = { 8C 06 73 6F 63 6B 65 74 [0-1] 8C 06 73 6F 63 6B 65 74 [0-1] 93 }
        $p2_request = /curllib\.request\nurlopen\n/
        $p2_http    = /chttp\.client\n/
        $p2_telnet  = /ctelnetlib\n/

        $bind_shell = "AF_INET"

    condition:
        $pkl_proto and
        (any of ($p2_*) or $p4_socket) and
        $bind_shell
}

rule Pickle_Encoded_Payload
{
    meta:
        description = "Pickle file with base64/hex encoded payloads (evasion)"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0018"
        severity    = "high"

    strings:
        $pkl_proto = { 80 ( 02 | 03 | 04 | 05 ) }

        $p2_codecs   = "ccodecs\ndecode\n"
        $p4_codecs   = { 8C 06 63 6F 64 65 63 73 [0-1] 8C 06 64 65 63 6F 64 65 [0-1] 93 }
        $p2_base64   = "cbase64\nb64decode\n"
        $p4_base64   = { 8C 06 62 61 73 65 36 34 [0-1] 8C 09 62 36 34 64 65 63 6F 64 65 [0-1] 93 }
        $p2_marshal  = "cmarshal\nloads\n"
        $p4_marshal  = { 8C 07 6D 61 72 73 68 61 6C [0-1] 8C 05 6C 6F 61 64 73 [0-1] 93 }

        // Long base64 inside SHORT_BINUNICODE / BINUNICODE
        $b64_blob_short = /\x8c[\x40-\xff][A-Za-z0-9+\/]{60,}={0,2}/
        $b64_blob_long  = /\x8d.{4}[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        $pkl_proto and
        any of ($p2_codecs, $p4_codecs, $p2_base64, $p4_base64, $p2_marshal, $p4_marshal) and
        any of ($b64_blob_*)
}

rule Pickle_HuggingFace_Hidden_File
{
    meta:
        description = "Suspicious pickle inside a HuggingFace ZIP/snapshot with non-standard extension"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0010.003"
        owasp       = "LLM03:2025"
        reference   = "https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face"
        severity    = "high"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $pkl_proto = { 80 ( 02 | 03 | 04 | 05 ) }

        $hidden_1 = ".bin"
        $hidden_2 = ".dat"
        $hidden_3 = ".cfg"
        $hidden_4 = "._pycache_"
        $hidden_5 = "data.pkl.gz"

        $danger_p2 = /c(os|subprocess|builtins|socket|codecs)\n/
        $danger_p4 = { 8C ( 02 6F 73 | 0A 73 75 62 70 72 6F 63 65 73 73 | 08 62 75 69 6C 74 69 6E 73 | 06 73 6F 63 6B 65 74 | 06 63 6F 64 65 63 73 ) }

    condition:
        $zip_magic at 0 and
        $pkl_proto and
        any of ($danger_*) and
        any of ($hidden_*)
}
