# GitHub Repository Description Options

1. **Technical:**
Authenticode signature manipulation toolkit. Steal signatures, hijack 19 SIP types, bypass WinVerifyTrust via FinalPolicy redirect, embed payloads in PKCS#7 unsignedAttrs, and install SIP execution surface implants. C++, Python, and BOFs for Cobalt Strike and Adaptix.

2. **Operator-focused:**
Red team toolkit for Windows trust manipulation. Steal a Microsoft signature, make it validate with one registry write, embed a payload that survives signature verification, and persist through the SIP execution surface. Works locally or remotely via Impacket.

3. **Research-focused:**
Windows Authenticode research toolkit covering SIP provider hijacking, Trust Provider FinalPolicy manipulation, PKCS#7 unauthenticated attribute embedding, and CryptDllFormatObject persistence. Includes 19 SIP GUIDs, Smart App Control bypass, and detection rules.

4. **Bypass-first:**
One registry write makes every signature check on a Windows machine return Valid. TrustMeBro redirects WinVerifyTrust FinalPolicy to SoftpubCleanup, hijacks 19 SIP types, embeds payloads inside valid Authenticode signatures, and bypasses Smart App Control on Win11.

5. **Breadth-first:**
Signature stealing, metadata cloning, SIP hijacking (19 GUIDs), FinalPolicy bypass, PKCS#7 payload embedding (direct and camouflage), SIP execution surface implants, CryptDllFormatObject persistence, CI probe, and Smart App Control bypass. C++, Python, BOFs.
