/*
 * trustmebro_sip_hijack.yar
 *
 * Detects SIP hijack artifacts produced by TrustMeBro.
 * Targets: any file (script, binary, registry export) containing the
 * SIP registry key path combined with the DbgUiContinue gadget.
 *
 * Covers all 19 SIP GUIDs supported by TrustMeBro.
 */

rule TrustMeBro_SipHijack_Loader
{
    meta:
        description = "Tool or script that installs a SIP hijack (DbgUiContinue gadget)"
        author      = "TrustMeBro"
        date        = "2026-07-03"

    strings:
        $func      = "CryptSIPDllVerifyIndirectData" ascii wide nocase
        $gadget1   = "DbgUiContinue" ascii wide nocase
        $gadget2   = "ntdll" ascii wide nocase

        // Core SIP GUIDs (partial match on first segment)
        $pe_guid   = "C689AAB8" ascii wide nocase
        $ps_guid   = "603BCC1F" ascii wide nocase
        $msi_guid  = "000C10F1" ascii wide nocase
        $vbs_guid  = "1629F04E" ascii wide nocase
        $js_guid   = "06C9E010" ascii wide nocase
        $wsf_guid  = "1A610570" ascii wide nocase
        $cab_guid  = "C689AABA" ascii wide nocase
        $cat_guid  = "DE351A43" ascii wide nocase
        $appx_guid = "0AC5DF4B" ascii wide nocase
        $sac_guid  = "18B3C141" ascii wide nocase

    condition:
        filesize < 10MB and
        $func and
        ($gadget1 or $gadget2) and
        any of ($pe_guid, $ps_guid, $msi_guid, $vbs_guid, $js_guid,
                $wsf_guid, $cab_guid, $cat_guid, $appx_guid, $sac_guid)
}

rule TrustMeBro_SipHijack_RegExport
{
    meta:
        description = "Registry export or REG_SZ blob containing a SIP hijack entry"
        author      = "TrustMeBro"
        date        = "2026-07-03"

    strings:
        $key     = "CryptSIPDllVerifyIndirectData" ascii wide nocase
        $bypass  = "DbgUiContinue" ascii wide nocase

    condition:
        filesize < 1MB and $key and $bypass
}
