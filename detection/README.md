# Detection Rules

YARA and Sigma rules for detecting TrustMeBro techniques. Test your payloads against these before deployment.

## Rules

| File | Format | Detects |
|---|---|---|
| `trustmebro_sip_hijack.yar` | YARA | SIP hijack loader/script containing DbgUiContinue + SIP GUIDs. Also catches registry exports with hijack entries. |
| `trustmebro_sip_hijack_registry.sigma` | Sigma | Registry write to CryptSIPDllVerifyIndirectData keys (Sysmon Event ID 13). |
| `trustmebro_finalpolicy_hijack.sigma` | Sigma | FinalPolicy registration under non-standard action GUID with SoftpubCleanup. |
| `trustmebro_sigstash_embed.yar` | YARA | SigStash tooling referencing PKCS#7 unsignedAttrs OIDs. Also flags signed PEs with WIN_CERTIFICATE larger than 32KB (possible embedded payload). |

## Usage

```bash
# Scan a file against all YARA rules
yara detection/trustmebro_sip_hijack.yar target.exe
yara detection/trustmebro_sigstash_embed.yar target.exe

# Scan a directory
yara -r detection/trustmebro_sip_hijack.yar C:\Temp\
```

Sigma rules require a SIEM or log pipeline. Convert with `sigma-cli` or `sigmac` for your backend.
