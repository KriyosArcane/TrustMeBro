# Detection Rules

Rules for detecting TrustMeBro techniques and related Authenticode manipulation.

## Rule Index

| Rule | Format | Technique | Targets |
|---|---|---|---|
| sip_hijack_registry.yar | YARA | SIP hijack via CryptSIPDllVerifyIndirectData redirect | Own technique |
| sip_hijack_gate1.yar | YARA | SIP hijack variant detection | Own technique |
| sip_hijack_registry_modify.sigma | Sigma | Registry modification of SIP provider keys | Own technique |
| shape2_dual_signerinfo.yar | YARA | Dual SignerInfo in WIN_CERTIFICATE | External detection |
| esbcache_bypass.yar | YARA | ESBCACHE EA manipulation artifacts | External detection |
| esbcache_bypass.sigma | Sigma | ESBCACHE bypass service creation | External detection |
| b1_ffi_behavior.sigma | Sigma | B1 FFI race behavior indicators | External detection |

## Usage

Operators should test their payloads against these rules before deployment. Rules marked "Own technique" detect techniques TrustMeBro implements. Rules marked "External detection" cover related CI bypass techniques operators may encounter.
