# Windows SIP Provider Map

Complete Subject Interface Package (SIP) GUID reference for Windows Authenticode.
Covers all registered SIP providers on Windows 10 22H2 and Windows 11 24H2.

Source: Reverse engineering of WINTRUST.DLL, MSISIP.DLL, pwrshsip.dll, wshext.dll, AppxSip.dll, EsdSip.dll via Ghidra headless analysis.

## SIP Provider Registry

| # | GUID | File Type | Handler DLL | Status |
|---|---|---|---|---|
| 1 | `{C689AAB8-8E78-11D0-8C47-00C04FC295EE}` | PE (.exe/.dll/.sys/.ocx) | WINTRUST.DLL | Verified |
| 2 | `{C689AAB9-8E78-11D0-8C47-00C04FC295EE}` | Java (.class) | WINTRUST.DLL | Legacy |
| 3 | `{C689AABA-8E78-11D0-8C47-00C04FC295EE}` | Cabinet (.cab) | WINTRUST.DLL | Verified |
| 4 | `{000C10F1-0000-0000-C000-000000000046}` | MSI (.msi/.msp) | MSISIP.DLL | Verified |
| 5 | `{603BCC1F-4B59-4E08-B724-D2C6297EF351}` | PowerShell (.ps1/.psm1/.psd1/.cdxml/.mof) | pwrshsip.dll | Verified |
| 6 | `{06C9E010-38CE-11D4-A2A3-00104BD35090}` | JScript (.js/.jse) | wshext.dll | Verified |
| 7 | `{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}` | VBScript (.vbs/.vbe) | wshext.dll | Verified |
| 8 | `{1A610570-38CE-11D4-A2A3-00104BD35090}` | WSF (.wsf/.wsc) | wshext.dll | Verified |
| 9 | `{0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}` | AppX/MSIX (.appx/.msix) | AppxSip.dll | Present |
| 10 | `{0F5F58B3-AADE-4B9A-A434-95742D92ECEB}` | AppX Bundle (.appxbundle/.msixbundle) | AppxSip.dll | Present |
| 11 | `{CF78C6DE-64A2-4799-B506-89ADFF5D16D6}` | Encrypted AppX (.eappx/.emsix) | AppxSip.dll | Present |
| 12 | `{D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C}` | Encrypted AppX Bundle (.eappxbundle) | AppxSip.dll | Present |
| 13 | `{5598CFF1-68DB-4340-B57F-1CACF88C9A51}` | P7X (.p7x) | AppxSip.dll | Present |
| 14 | `{1AD2DCB4-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` | AppX Extensions (Win11) | AppxSip.dll | Win11 only |
| 15 | `{9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}` | CTL (.ctl/.stl) | WINTRUST.DLL | Verified |
| 16 | `{DE351A42-8E59-11D0-8C47-00C04FC295EE}` | Flat/raw (fallback) | WINTRUST.DLL | Present |
| 17 | `{DE351A43-8E59-11D0-8C47-00C04FC295EE}` | Catalog (.cat) | WINTRUST.DLL | Verified |
| 18 | `{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}` | ESD/WIM (Windows images) | EsdSip.dll | Present |
| 19 | `{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}` | Smart App Control (Win11) | WINTRUST.DLL | Win11 only |

## Handler DLL Distribution

| DLL | Count | File Types |
|---|---|---|
| WINTRUST.DLL | 8 | PE, Java, Cabinet, CTL, Flat, Catalog, Smart App Control, Win11 internal |
| MSISIP.DLL | 1 | MSI |
| pwrshsip.dll | 1 | PowerShell |
| wshext.dll | 3 | JScript, VBScript, WSF |
| AppxSip.dll | 5 | AppX, AppX Bundle, Encrypted AppX, Encrypted AppX Bundle, P7X, Extensions |
| EsdSip.dll | 1 | ESD/WIM |

## File Type Detection Methods

Each SIP provider uses a different method to identify its file type. Windows calls `CryptSIPDllIsMyFileType2` (if registered) or uses builtin detection in WINTRUST.DLL.

| GUID | Detection Method |
|---|---|
| `C689AAB8` | MZ + PE magic (builtin WINTRUST) |
| `C689AAB9` | 0xCAFEBABE magic (builtin WINTRUST) |
| `C689AABA` | MSCF magic (builtin WINTRUST) |
| `DE351A42` | Fallback (no other SIP matched) |
| `DE351A43` | PKCS#7 CTL OID presence (builtin WINTRUST) |
| `9BA61D3F` | PKCS#7 CTL OID presence (builtin WINTRUST) |
| `18B3C141` | Builtin WINTRUST internal dispatch (no IsMyFileType2) |
| `000C10F1` | StgOpenStorage + OLE CLSID (MSI is OLE compound document) |
| `603BCC1F` | PsIsMyFileType (pwrshsip.dll) checks .ps1/.psm1/.psd1/.cdxml/.mof extensions |
| `06C9E010` | Extension match: `.js`, `.jse` |
| `1629F04E` | Extension match: `.vbs`, `.vbe` |
| `1A610570` | Extension match: `.wsf` |
| `0AC5DF4B` | Extension match: `.appx`, `.msix`, `.pkgSignConfig`, `.tmp` |
| `0F5F58B3` | Extension match: `.appxbundle`, `.msixbundle`, `.pkgSignConfig` |
| `CF78C6DE` | IStream read + encrypted AppX format header |
| `D1D04F0C` | IStream read + encrypted AppX Bundle format header |
| `5598CFF1` | SHCreateStreamOnFileEx + IStream P7X magic read |
| `9F3053C5` | `MSWIM` magic (0x4D4957534D) + header size 0xD0 |
| `1AD2DCB4` | ExtensionsSipIsFileSupportedName (AppxSip internal) |

## Registry Structure

All SIP functions are registered under `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\` with the following subkeys per GUID:

```
CryptSIPDllGetSignedDataMsg\{GUID}     → Extracts signature from file
CryptSIPDllPutSignedDataMsg\{GUID}     → Writes signature to file
CryptSIPDllRemoveSignedDataMsg\{GUID}  → Removes signature from file
CryptSIPDllCreateIndirectData\{GUID}   → Creates hash for signing
CryptSIPDllVerifyIndirectData\{GUID}   → Verifies hash matches file
CryptSIPDllIsMyFileType2\{GUID}        → (Optional) File type detection
```

Each subkey contains:
- `Dll` (REG_SZ): Path to the handler DLL
- `FuncName` (REG_SZ): Export name to call

## Smart App Control SIP (GUID #19)

**Windows 11 only.** Not present on Windows 10.

Discovered via Ghidra reverse engineering of Windows 11 24H2 WINTRUST.DLL. Located in builtin GUID table at .rdata offset 0x62410.

Related kernel extended attributes:
- `$Kernel.Smartlocker.OriginClaim` (file origin tracking)
- `$Kernel.Purge.Smartlocker.Valid` (cached validation result)
- `$Kernel.Smartlocker.Hash` (file hash for SAC decisions)

Related export: `SrpCheckSmartlockerEAandProcessToken`

This GUID is used internally by Smart App Control to verify unsigned/untrusted binaries. It is dispatched by WINTRUST.DLL without a user-facing IsMyFileType2 registration.

## Verification Results

| Category | Count |
|---|---|
| Verified on Win10 22H2 + Win11 24H2 | 9 |
| Present but not independently tested | 8 |
| Windows 11 only | 2 |
| Legacy (no modern use) | 1 |
| **Total registered SIP GUIDs** | **19** |

## References

- MITRE ATT&CK T1553.003 (Subvert Trust Controls: SIP and Trust Provider Hijacking)
- Microsoft documentation: "How SIPs are Registered"
- Matt Graeber, "Subverting Trust in Windows" (2017)
- TrustMeBro toolkit: github.com/KriyosArcane/TrustMeBro
