# FormatGhost

FormatGhost is a small Windows research tool for `CryptDllFormatObject`.

## What `CryptDllFormatObject` does

Windows lets admins register custom OID format handlers under:

`HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptDllFormatObject\<OID>`

When code such as `certutil -dump` or certificate UI needs to display an object for that OID, CryptoAPI can load the registered DLL and call the named export.

## Attack chain

1. Register an OID handler in `CryptDllFormatObject`.
2. Embed data under that OID in PKCS#7 attributes inside a PE signature blob.
3. A user or analyst runs `certutil -dump` or opens cert UI on that PE.
4. Windows loads the DLL and calls the registered formatter.

This tool gives you two pieces:

- `register.py` for registry setup and cleanup
- `format_ghost.c` for a minimal formatter DLL

## Requirements

- Windows
- Admin rights to write the `HKLM` OID registration key
- Python 3 for `register.py`
- MinGW-w64 for the sample DLL build

## Limitations

- This is not automatic execution
- It needs admin access for registration
- It needs user interaction or analyst action
- The sample DLL only captures the raw attribute bytes and returns `FALSE`
- The sample does not embed the OID into a PE for you

## Build

From this directory:

```sh
make
```

This produces `format_ghost.dll`.

## Usage

Register a handler:

```sh
python register.py --oid 1.2.3.4.5555 --dll C:\Path\format_ghost.dll --funcname FormatObject
```

Remove the handler:

```sh
python register.py --oid 1.2.3.4.5555 --clean
```

Build the DLL:

```sh
make clean && make
```

Trigger the load path after you place the OID in PKCS#7 attributes:

```sh
certutil -dump sample.exe
```

On first callback, the sample DLL writes the raw attribute bytes to:

`%TEMP%\format_ghost_payload.bin`

## Notes

Keep this tool separate from TrustMeBro workflows. It does not share code with the main project.
