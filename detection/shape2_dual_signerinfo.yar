/*
 * shape2_dual_signerinfo.yar — YARA rules for dual-SignerInfo PE artifacts
 *
 * Reference: lab/poc/shape2-signerinfo-dual/ PoC
 * Primitive: parser-disagreement — shape2 dual SignerInfo PE structure
 *
 * Detection coverage:
 *   A. PE file containing a WIN_CERTIFICATE blob with 2+ SignerInfo entries
 *      (generic CMS allows it; signify.authenticode rejects it)
 *   B. The builder script itself
 *
 * Note on A: this cannot be detected by a pure byte-pattern rule reliably
 * without parsing the CMS structure. The condition here is an approximation:
 * two distinct SignerInfo OID sequences at close range within the security directory.
 * False positive rate is low on real signed PEs but not zero.
 * Authoritative detection requires a structured parser (certutil -dump, asn1crypto).
 */

rule ResearchLab_Shape2_DualSignerInfo_PE
{
    meta:
        description    = "PE with WIN_CERTIFICATE containing multiple SignerInfo entries (Authenticode parser disagreement)"
        author         = "Research"
        date           = "2026-06-03"
        reference      = "lab/poc/shape2-signerinfo-dual/docs/DESIGN.md"
        confidence     = "medium"
        primitive      = "shape2-parser-disagreement"
        note           = "Heuristic — structured parser (asn1crypto) is authoritative"

    strings:
        // WIN_CERTIFICATE magic: wRevision=0x0200 wCertificateType=0x0002
        $wincert_hdr = { ?? ?? ?? ?? 00 02 02 00 }
        // PKCS#7 SignedData OID: 1.2.840.113549.1.7.2
        $sd_oid      = { 06 09 2A 86 48 86 F7 0D 01 07 02 }
        // SignerInfo SEQUENCE tag + version=1 (02 01 01) appears twice for dual-signer
        $si_version  = { 30 ?? 02 01 01 }

    condition:
        uint16(0) == 0x5A4D and                     // MZ header
        $wincert_hdr and $sd_oid and
        #si_version >= 2 and                         // at least 2 SignerInfo blocks
        @si_version[2] - @si_version[1] < 8192       // both within 8KB of each other
}

rule ResearchLab_Shape2_Builder
{
    meta:
        description    = "shape2_pe.py builder script that constructs dual-SignerInfo Authenticode blobs"
        author         = "Research"
        date           = "2026-06-03"
        reference      = "lab/poc/shape2-signerinfo-dual/builder/shape2_pe.py"
        confidence     = "high"
        primitive      = "shape2-parser-disagreement"

    strings:
        $s1 = "dual-SignerInfo" ascii
        $s2 = "SpcIndirectDataContent" ascii
        $s3 = "_build_signed_data" ascii
        $s4 = "WIN_CERTIFICATE" ascii
        $s5 = "shape2_pe" ascii

    condition:
        3 of ($s1, $s2, $s3, $s4, $s5)
}
