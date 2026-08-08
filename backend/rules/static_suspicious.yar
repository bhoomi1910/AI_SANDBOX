rule SUSP_Process_Injection_APIs
{
    meta:
        description = "Classic CreateRemoteThread process injection triad imported together"
        author = "Sandbox Research"
        severity = "high"
        mitre = "T1055"
        tags = "injection, evasion"
    strings:
        $a = "VirtualAllocEx" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "CreateRemoteThread" ascii wide
    condition:
        all of them
}

rule SUSP_AntiDebug_Checks
{
    meta:
        description = "Debugger-detection APIs (IsDebuggerPresent / CheckRemoteDebuggerPresent)"
        author = "Sandbox Research"
        severity = "medium"
        mitre = "T1622"
        tags = "anti-debug, evasion"
    strings:
        $a = "IsDebuggerPresent" ascii wide
        $b = "CheckRemoteDebuggerPresent" ascii wide
    condition:
        any of them
}

rule SUSP_Shell_Execution
{
    meta:
        description = "Shell / script execution primitives (cmd, PowerShell, WScript, rundll32, mshta)"
        author = "Sandbox Research"
        severity = "high"
        tags = "execution, lolbin"
    strings:
        $a = "cmd.exe" ascii wide
        $b = "powershell" ascii wide nocase
        $c = "WScript.Shell" ascii wide nocase
        $d = "rundll32" ascii wide nocase
        $e = "mshta" ascii wide nocase
        $f = "certutil" ascii wide nocase
    condition:
        any of them
}

rule SUSP_Reg_Run_Key_Persistence
{
    meta:
        description = "References to the registry Run key used for persistence"
        author = "Sandbox Research"
        severity = "high"
        mitre = "T1547.001"
        tags = "persistence, registry"
    strings:
        $a = "CurrentVersion\\Run" ascii wide nocase
        $b = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $c = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    condition:
        any of them
}

rule SUSP_UrlDownload
{
    meta:
        description = "HTTP(S) URLs embedded in the binary (potential C2 / payload delivery)"
        author = "Sandbox Research"
        severity = "medium"
        tags = "network, c2"
    strings:
        $a = /https?:\/\/[a-zA-Z0-9\.\-]+\.[a-z]{2,}[^\s]{0,80}/
        $b = /ftp:\/\/[^\s]{5,}/
    condition:
        any of them
}

rule SUSP_Windows_Service_Install
{
    meta:
        description = "APIs/strings associated with installing a Windows service"
        author = "Sandbox Research"
        severity = "medium"
        mitre = "T1543.003"
        tags = "persistence"
    strings:
        $a = "CreateServiceA" ascii wide
        $b = "CreateServiceW" ascii wide
        $c = "StartServiceA" ascii wide
        $d = "OpenSCManagerA" ascii wide
    condition:
        any of them
}

rule SUSP_Obfuscation_Base64
{
    meta:
        description = "Base64 encoding primitives commonly used to hide payloads"
        author = "Sandbox Research"
        severity = "low"
        tags = "obfuscation"
    strings:
        $a = "CryptBinaryToStringA" ascii wide
        $b = "fromBase64" ascii wide nocase
        $c = "ToBase64" ascii wide nocase
    condition:
        any of them
}

rule SUSP_DownloadString_PowerShell
{
    meta:
        description = "PowerShell download-and-execute primitive (Invoke-Expression + Invoke-WebRequest / DownloadString)"
        author = "Sandbox Research"
        severity = "critical"
        mitre = "T1059.001"
        tags = "downloader, powershell"
    strings:
        $a = "DownloadString" ascii wide nocase
        $b = "Invoke-Expression" ascii wide nocase
        $c = "IEX" ascii wide nocase
    condition:
        $a and any of ($b,$c)
}

rule SUSP_VBScript_Host
{
    meta:
        description = "VBScript host / scripting objects (dropper or macro payload)"
        author = "Sandbox Research"
        severity = "medium"
        tags = "dropper, macro"
    strings:
        $a = "WScript.Shell" ascii wide nocase
        $b = "CreateObject" ascii wide nocase
        $c = "Scripting.FileSystemObject" ascii wide nocase
        $d = "adodb.stream" ascii wide nocase
    condition:
        $a and any of ($b,$c,$d)
}
