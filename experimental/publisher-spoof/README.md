# Publisher Name Spoofing (Experimental)

This experiment generates a self-signed certificate chain with a caller-supplied Common Name (CN), places the resulting publisher certificate in the TrustedPublisher store, and uses it to sign a PE. When combined with a SIP hijack or FinalPolicy hijack, the UAC dialog can present the chosen publisher name.

## Requirements

- Administrator access
- `osslsigncode` or `signtool`

## Status

Experimental only. This is not merged into the main tool.

## Attack chain

1. Generate a self-signed certificate chain with `CN="Microsoft Corporation"` (or any name you choose).
2. Enroll the publisher certificate in the TrustedPublisher certificate store.
3. Sign your PE with this certificate.
4. Enable a SIP hijack or FinalPolicy hijack.
5. The UAC dialog shows `Verified publisher: Microsoft Corporation`.
