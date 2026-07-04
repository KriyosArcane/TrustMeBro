/*
 * esbcache_bypass.yar — Detection for $Kernel.Purge.ESBCache offline injection
 *
 * Primitive: ESBCACHE EA cache bypass (ci.dll CipVerifyFileCache flags bit 9)
 * Confirmed: 2026-06-04, ci.dll 26100.8328
 * Reference: lab/poc/b1-file-hash-ffi/cipverifyfilecache_full_analysis.md
 *
 * Attack: attacker writes a forged $Kernel.Purge.ESBCache EA (type 0xE0) directly
 * to an NTFS MFT record on a .sys file. When CI loads the driver, CipVerifyFileCache
 * reads the EA and returns STATUS_SUCCESS before any Authenticode validation.
 *
 * Detection targets:
 *   A. The esbcache_inject.py tool itself (contains EA name and struct constants)
 *   B. A raw NTFS image file containing an injected $Kernel.Purge.ESBCache EA
 *   C. A PE file that has had the EA injected (signature is absent or self-signed)
 *   D. The esbtest.sys proof-of-concept driver
 */

rule ResearchLab_ESBCACHE_InjectTool
{
    meta:
        description    = "Python script implementing $Kernel.Purge.ESBCache EA injection for CI bypass"
        author         = "Research"
        date           = "2026-06-04"
        reference      = "lab/poc/b1-file-hash-ffi/esbcache_inject.py"
        confidence     = "high"
        primitive      = "esbcache-bypass"

    strings:
        $name1  = "$Kernel.Purge.ESBCache" ascii wide
        $name2  = "Kernel.Purge.ESBCache" ascii
        $func1  = "CipVerifyFileCache" ascii
        $func2  = "CipGetFileCache" ascii
        $func3  = "CiBuildEaCacheContents" ascii
        $magic1 = { 1e 00 00 00 03 00 02 }    // EA value header: total=0x1e, magic=0x0003, variant=0x02
        $flag1  = { 20 00 00 00 00 00 }        // flags=0x20 at EA+0x18

    condition:
        filesize < 200KB and
        ($name1 or $name2) and
        ($func1 or $func2 or $func3) and
        ($magic1 or $flag1)
}

rule ResearchLab_ESBCACHE_MFT_Injected_Image
{
    meta:
        description    = "NTFS disk image containing a $Kernel.Purge.ESBCache $EA attribute (MFT 0xE0)"
        author         = "Research"
        date           = "2026-06-04"
        reference      = "lab/poc/b1-file-hash-ffi/ea_roundtrip_test.md"
        confidence     = "medium"
        primitive      = "esbcache-bypass"
        note           = "Matches raw NTFS images with injected EA. FPs: legitimate system volumes unlikely."

    strings:
        // NTFS EA attribute header: type=0xE0, followed by EA name
        $ea_attr  = { E0 00 00 00 }           // $EA attribute type
        $ea_name  = "$Kernel.Purge.ESBCache"  // EA name in MFT
        // EA value magic bytes
        $ea_magic = { 1e 00 00 00 03 00 02 }

    condition:
        $ea_attr and $ea_name and $ea_magic
}

rule ResearchLab_ESBCACHE_ProofDriver
{
    meta:
        description    = "esbtest.sys proof-of-concept driver for ESBCACHE bypass validation"
        author         = "Research"
        date           = "2026-06-04"
        reference      = "lab/poc/b1-file-hash-ffi/test_driver/esbtest.c"
        confidence     = "high"
        primitive      = "esbcache-bypass"

    strings:
        $s1 = "ESBCACHE_BYPASS_LOADED" ascii
        $s2 = "ESBCACHE_BYPASS_ACTIVE" ascii
        $s3 = "\\Device\\EsbBypass" wide
        $s4 = "\\DosDevices\\EsbBypass" wide
        $s5 = "ESBCacheBypass" wide
        $s6 = "esbtest" ascii

    condition:
        uint16(0) == 0x5A4D and         // MZ
        3 of ($s1, $s2, $s3, $s4, $s5, $s6)
}

rule ResearchLab_ESBCACHE_BypassAttempt_Registry
{
    meta:
        description    = "Registry artifact indicating esbtest.sys DriverEntry executed (ESBCACHE bypass)"
        author         = "Research"
        date           = "2026-06-04"
        reference      = "lab/poc/b1-file-hash-ffi/test_driver/esbtest.c"
        confidence     = "high"
        primitive      = "esbcache-bypass"
        note           = "Match .reg exports or registry hive files, not live registry"

    strings:
        $key = "ESBCacheBypass" ascii wide nocase
        $val = "Loaded" ascii wide
        $dword = { 01 00 00 00 }

    condition:
        $key and $val and $dword
}
