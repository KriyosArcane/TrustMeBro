# TrustMeBro

**TrustMeBro** is a comprehensive Authenticode signature manipulation tool designed for Red Team operations and security research. It unifies signature stealing, metadata cloning, and Subject Interface Package (SIP) hijacking into a single toolkit, available in both Python (cross-platform) and C++ (Windows native).

> **Note:** A rewritten, rust version of this tool is available here: [TrustMeBro-Rust](https://github.com/placeholder/TrustMeBro-Rust)

## Features

*   **Signature Stealing:** Extracts the Authenticode certificate table from a signed binary (e.g., `explorer.exe`) and appends it to a target payload.
*   **Metadata Cloning:** Copies the Version Info, Icon, and Manifest from a legitimate binary to the target, making it look identical in Properties.
*   **SIP Hijacking:** Modifies the Windows Registry to register a custom "Subject Interface Package" provider. This forces Windows to validate the stolen signature as "Valid" even though the hash doesn't match.
    *   Supports **PE Files** (`.exe`, `.dll`)
    *   Supports **PowerShell Scripts** (`.ps1`)
    *   Supports **MSI Installers** (`.msi`)

## How It Works

### 1. Signature Stealing
Windows Authenticode signatures are stored in the `IMAGE_DIRECTORY_ENTRY_SECURITY` slot of the PE Optional Header. This tool reads the certificate table from the source binary and appends it to the end of the target binary, updating the PE header to point to the new location.

### 2. Metadata Cloning
Using `objcopy` (Python) or native Windows APIs (C++), the tool extracts the `.rsrc` section (containing icons and version info) from a donor file and implants it into the target. It automatically fixes the Resource Directory Virtual Addresses (RVAs) to ensure icons render correctly.

### 3. SIP Hijacking
Windows uses "Subject Interface Packages" (SIPs) to verify signatures for different file types. By modifying specific keys in `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData`, we can redirect the verification process to a standard Windows DLL (`ntdll.dll`) that returns "Success" for our stolen signature, bypassing the hash check.

## Usage

### C++ Version (Windows Native)
Ideal for running directly on a compromised Windows host.

**Default Behavior (Hijack + Steal):**
By default, the tool will steal the signature/metadata AND hijack the local registry to make the signature valid.

```cmd
:: Steal signature, Clone Metadata, AND Hijack Registry (All-in-one)
TrustMeBro.exe --source C:\Windows\explorer.exe --target agent.exe --clone
```

**Steal Only (No Hijack):**
Use `--no-hijack` to only perform file modifications without touching the registry.

```cmd
:: Steal signature only (Invalid signature without hijack)
TrustMeBro.exe --source C:\Windows\explorer.exe --target agent.exe --no-hijack

:: Steal signature + Clone Metadata (No Hijack)
TrustMeBro.exe --source C:\Windows\explorer.exe --target agent.exe --clone --no-hijack
```

**Registry Cleanup:**
```cmd
:: Restore local registry keys to default
TrustMeBro.exe --clean
```

---

### Python Version (Cross-Platform)
Ideal for Linux users or scripting.

**Requirements:**
*   Python 3
*   `objcopy` (from `binutils`) OR `x86_64-w64-mingw32-objcopy` (from `mingw-w64-tools` - Recommended for best compatibility)

**Steal Signature & Clone Metadata:**
```bash
# Basic Steal
python3 TrustMeBro.py steal --source explorer.exe --target agent.exe

# Steal + Clone Metadata (Icon/Version)
python3 TrustMeBro.py steal --source explorer.exe --target agent.exe --clone
```

**SIP Hijacking (Remote Registry):**
Requires `impacket` for remote registry operations.
```bash
# Hijack the target machine to validate stolen signatures
python3 TrustMeBro.py hijack 192.168.1.10 -u Administrator -p Password123

# Restore registry to default
python3 TrustMeBro.py hijack 192.168.1.10 -u Administrator -p Password123 --action clean
```

## Disclaimer
This tool is intended for educational purposes and authorized security testing only. Misuse of this tool to attack systems without consent is illegal. The authors are not responsible for any damage caused by this software.

## Credits & Inspirations
Special thanks to the authors of the following tools for their pioneering research:

*   **[SignatureKid](https://github.com/dslee2022/SignatureKid)** by [David Lee](https://www.linkedin.com/in/davidl24/) - For the research on signature manipulation and the original code that this tool is based on.
*   **[MetaTwin](https://github.com/threatexpress/metatwin)** by ThreatExpress - For the concept of cloning binary metadata.