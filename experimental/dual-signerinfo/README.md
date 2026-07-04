# Dual-SignerInfo Emitter (Experimental)

This experiment would insert the payload as a second `SignerInfo` entry instead of hiding it in an `unsignedAttr`. The proposed camouflage differs from `SPC_NESTED_SIGNATURE`: kernel-side parsing appears to consume only `SignerInfo[0]`, while user-mode verification walks all signer entries.

## Status

Experimental only. Kernel behavior is unverified on current builds.

## Reference

- `lab/poc/shape2-signerinfo-dual/docs/DESIGN.md`

## Warning

This changes the `SignedData` structure at a deeper layer than `unsignedAttrs`. Primary signature validity depends on whether the parser tolerates multiple `SignerInfo` entries in the same `SignedData`.
