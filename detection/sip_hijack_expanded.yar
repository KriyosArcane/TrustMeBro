/*
 * sip_hijack_expanded.yar - Detects SIP hijack targeting non-PE file types
 *
 * TrustMeBro supports 9 SIP GUIDs. The original sip_hijack_registry.yar
 * only covers the PE GUID. This rule covers the 6 additional file types.
 */

rule TrustMeBro_SipHijack_ScriptSIP
{
    meta:
        description = "SIP hijack targeting VBScript, JScript, or WSF file types"
        author      = "TrustMeBro"
        date        = "2026-07-03"
        confidence  = "high"

    strings:
        $vbs_guid  = "1629F04E" ascii wide nocase
        $js_guid   = "06C9E010" ascii wide nocase
        $wsf_guid  = "1A610570" ascii wide nocase
        $func      = "CryptSIPDllVerifyIndirectData" ascii wide
        $bypass    = "DbgUiContinue" ascii wide nocase

    condition:
        $func and ($vbs_guid or $js_guid or $wsf_guid) and $bypass
}

rule TrustMeBro_SipHijack_PackageSIP
{
    meta:
        description = "SIP hijack targeting CAB, Catalog, or AppX file types"
        author      = "TrustMeBro"
        date        = "2026-07-03"
        confidence  = "high"

    strings:
        $cab_guid  = "C689AABA" ascii wide nocase
        $cat_guid  = "DE351A43" ascii wide nocase
        $appx_guid = "0AC5DF4B" ascii wide nocase
        $func      = "CryptSIPDllVerifyIndirectData" ascii wide
        $bypass    = "DbgUiContinue" ascii wide nocase

    condition:
        $func and ($cab_guid or $cat_guid or $appx_guid) and $bypass
}
