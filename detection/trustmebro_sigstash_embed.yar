/*
 * trustmebro_sigstash_embed.yar
 *
 * Detects tools or PEs that embed/extract payloads in PKCS#7
 * unauthenticated attributes (SigStash technique).
 * Targets: TrustMeBro embed tooling, SigStash loader, or carrier PEs
 * with an unusually large WIN_CERTIFICATE region.
 */

rule TrustMeBro_SigStash_Tool
{
    meta:
        description = "Tool that embeds or extracts payloads from PKCS#7 unsignedAttrs"
        author      = "TrustMeBro"
        date        = "2026-07-03"

    strings:
        $oid_default = "1.3.6.1.4.1.311.99.1" ascii wide
        $oid_nested  = "1.3.6.1.4.1.311.2.4.1" ascii wide
        $func1       = "unsignedAttrs" ascii wide nocase
        $func2       = "unauthenticated" ascii wide nocase
        $func3       = "SPC_NESTED_SIGNATURE" ascii wide nocase
        $func4       = "sigstash" ascii wide nocase

    condition:
        filesize < 10MB and
        ($oid_default or $oid_nested) and
        any of ($func1, $func2, $func3, $func4)
}

rule TrustMeBro_SigStash_LargeCert
{
    meta:
        description = "Signed PE with unusually large WIN_CERTIFICATE (possible embedded payload)"
        author      = "TrustMeBro"
        date        = "2026-07-03"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 4096 and
        // PE32+ security directory size at OptionalHeader + 0x98
        uint32(uint32(0x3C) + 0x98) > 0 and
        uint32(uint32(0x3C) + 0x9C) > 32768
}
