/*
 * sip_hijack.yar — YARA rules for SIP hijack / CryptSIPDll forgery artifacts
 *
 * Reference: lab/poc/sip-hijack/ PoC, references/11_sip_hijack_and_lolcerts.md
 * Primitive: CLAUDE.md §"four primitives" #1
 * Confidence: high (registry key string combination is distinctive)
 *
 * Detection coverage:
 *   A. PowerShell loader that writes the SIP hijack registry key
 *   B. Any binary referencing both the PE SIP GUID and DbgUiContinue
 *   C. Registry export (.reg) containing the hijacked key
 */

rule ResearchLab_SipHijack_PSLoader
{
    meta:
        description    = "PowerShell script that installs SIP hijack targeting {C689AAB8} PE SIP GUID"
        author         = "Research"
        date           = "2026-06-03"
        reference      = "lab/poc/sip-hijack/loader.ps1"
        confidence     = "high"
        primitive      = "sip-hijack"
        mitre_attack   = "T1553.002"

    strings:
        $guid    = "{C689AAB8-14B6-11d2-BD56-0000F803049C}" ascii wide nocase
        $func1   = "CryptSIPDllVerifyIndirectData" ascii wide
        $target1 = "DbgUiContinue" ascii wide
        $target2 = "ntdll" ascii wide

    condition:
        filesize < 500KB and
        $guid and $func1 and ($target1 or $target2)
}

rule ResearchLab_SipHijack_RegistryExport
{
    meta:
        description    = "Registry .reg file or REG_SZ blob containing SIP hijack entry for PE GUID"
        author         = "Research"
        date           = "2026-06-03"
        reference      = "lab/poc/sip-hijack/loader.ps1"
        confidence     = "high"
        primitive      = "sip-hijack"

    strings:
        $key     = "CryptSIPDllVerifyIndirectData" ascii wide nocase
        $guid    = "C689AAB8" ascii wide nocase
        $bypass1 = "DbgUiContinue" ascii wide nocase
        $bypass2 = "AlwaysTrue" ascii wide nocase

    condition:
        $key and $guid and ($bypass1 or $bypass2)
}

rule ResearchLab_SipHijack_BinaryLoader
{
    meta:
        description    = "PE binary that manipulates CryptSIPDll registry keys to install SIP hijack"
        author         = "Research"
        date           = "2026-06-03"
        reference      = "references/11_sip_hijack_and_lolcerts.md §Part 1"
        confidence     = "medium"
        primitive      = "sip-hijack"
        note           = "May FP on legitimate SIP registration tools"

    strings:
        $reg_key  = "CryptSIPDll" ascii wide
        $guid     = "C689AAB8" ascii wide nocase
        $reg_api1 = "RegSetValueEx" ascii wide
        $reg_api2 = "RegCreateKeyEx" ascii wide

    condition:
        filesize < 10MB and
        $reg_key and $guid and ($reg_api1 or $reg_api2)
}
