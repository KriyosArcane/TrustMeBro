# Dual-SignerInfo technical notes

- Kernel `ci.dll` `MinAsn1ParseSignedData` appears to extract exactly one signer via a template-driven path and does not loop over the `SignerInfos` set.
- User-mode `wintrust` / Crypt32 processing enumerates `CMSG_SIGNER_COUNT_PARAM`, so it can observe every signer entry present in the `SignedData`.
- The asymmetry suggests a layout where the operator-controlled signer sits at index `[0]` and the benign-looking chain sits at index `[1]`.
- This is **not** the same thing as a dual-signed PE. Dual-signed PEs carry two separate `WIN_CERTIFICATE` blobs.
- Here, both signer records live inside a **single** `SignedData` object as two `SignerInfo` entries.
- Current lab notes for Win11 24H2:
  - Kernel signer stride `0xF0` appears unchanged.
  - BER long-form lengths are still rejected at `0x86BAA`.

No emitter code is included here. The ASN.1 rewrites needed for a real implementation require lab validation before they should exist in-tree.
