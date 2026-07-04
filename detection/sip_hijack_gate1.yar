/*
 * sip_hijack_gate1.yar — Gate 1 artifact fingerprint for the SIP hijack primitive
 *
 * Reference:     lab/poc/sip-hijack/loader.ps1, test_harness.ps1
 * Experiment:    2026-06-04 — TRUST_E_NOSIGNATURE (0x800B0100) returned; Gate 1 FAIL
 * Gate status:   Gate 1 FAIL — SIP dispatch reached but signature chain not bypassed;
 *                deeper wintrust trace required.
 * MITRE:         T1553.002 (Code Signing — SIP hijack)
 *
 * Matching criteria (all three required for high-confidence hit):
 *   1. PE SIP GUID present: {C689AAB8-14B6-...} OR {C689AAB8-8E78-...}
 *   2. ntdll!DbgUiContinue as the registered handler (the null-stub approach)
 *   3. CryptSIPDllVerifyIndirectData registry value name
 *
 * The combination of all three is unique to the SIP hijack setup tool.
 * Partial matches (two of three) are flagged at medium confidence.
 */

rule ResearchLab_SipHijack_Gate1_FullIndicator
{
    meta:
        description    = "Full indicator: SIP hijack setup tool containing both PE SIP GUIDs, DbgUiContinue handler ref, and CryptSIPDllVerifyIndirectData"
        author         = "Research"
        date           = "2026-06-04"
        reference      = "lab/poc/sip-hijack/loader.ps1"
        gate           = "Gate1"
        experiment     = "2026-06-04 TRUST_E_NOSIGNATURE result"
        confidence     = "high"
        mitre_attack   = "T1553.002"
        primitive      = "sip-hijack"

    strings:
        // Condition 1: PE SIP GUID — 14B6 variant (CryptSIPDllVerifyIndirectData handler slot)
        $guid_14b6      = "{C689AAB8-14B6-11d2-BD56-0000F803049C}" ascii wide nocase

        // Condition 1 (alt): PE SIP GUID — 8E78 variant (CryptSIPDllGetSignedDataMsg handler slot)
        $guid_8e78      = "{C689AAB8-8E78-11d2-BD56-0000F803049C}" ascii wide nocase

        // Condition 1 (bare hex, for reg exports and fragmented strings)
        $guid_bare      = "C689AAB8" ascii wide nocase

        // Condition 2: ntdll + DbgUiContinue (the null-stub handler)
        $handler_ntdll  = "ntdll" ascii wide nocase
        $handler_func   = "DbgUiContinue" ascii wide

        // Condition 3: registry value name targeted
        $reg_value      = "CryptSIPDllVerifyIndirectData" ascii wide

    condition:
        filesize < 2MB and
        ($guid_14b6 or $guid_8e78 or $guid_bare) and
        ($handler_ntdll and $handler_func) and
        $reg_value
}

rule ResearchLab_SipHijack_Gate1_PartialMatch
{
    meta:
        description    = "Partial match: two of three SIP hijack indicators present — investigate further"
        author         = "Research"
        date           = "2026-06-04"
        reference      = "lab/poc/sip-hijack/loader.ps1"
        gate           = "Gate1"
        confidence     = "medium"
        mitre_attack   = "T1553.002"
        primitive      = "sip-hijack"
        note           = "May FP on SIP documentation, MSDN samples, or security research tools"

    strings:
        $guid_14b6      = "{C689AAB8-14B6-11d2-BD56-0000F803049C}" ascii wide nocase
        $guid_8e78      = "{C689AAB8-8E78-11d2-BD56-0000F803049C}" ascii wide nocase
        $guid_bare      = "C689AAB8" ascii wide nocase
        $handler_func   = "DbgUiContinue" ascii wide
        $reg_value      = "CryptSIPDllVerifyIndirectData" ascii wide

    condition:
        filesize < 10MB and
        (
            // GUID + handler (no reg value name — possibly compiled loader)
            (($guid_14b6 or $guid_8e78 or $guid_bare) and $handler_func) or
            // GUID + reg value name (no handler — possibly config/export/reg file)
            (($guid_14b6 or $guid_8e78) and $reg_value) or
            // Handler + reg value name (no GUID — possibly generic SIP tampering tool)
            ($handler_func and $reg_value)
        )

    // Exclude the full-indicator rule's hits to avoid double-reporting
    // (scanners that support rule dependencies can reference Gate1_FullIndicator here)
}
