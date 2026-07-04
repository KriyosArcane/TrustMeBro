#!/usr/bin/env python3
import argparse
import platform
import sys


REG_PATH_PREFIX = r"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptDllFormatObject"


def require_windows():
    if platform.system() != "Windows":
        print("error: register.py only works on Windows", file=sys.stderr)
        sys.exit(1)


def load_winreg():
    try:
        import winreg  # type: ignore
    except ImportError as exc:
        print(f"error: failed to import winreg: {exc}", file=sys.stderr)
        sys.exit(1)
    return winreg


def target_path(oid: str) -> str:
    return fr"{REG_PATH_PREFIX}\{oid}"


def register_oid(winreg, oid: str, dll: str, funcname: str) -> None:
    path = target_path(oid)
    wow64_flag = getattr(winreg, "KEY_WOW64_64KEY", 0)
    access = winreg.KEY_WRITE | wow64_flag

    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, access) as key:
            winreg.SetValueEx(key, "Dll", 0, winreg.REG_SZ, dll)
            winreg.SetValueEx(key, "FuncName", 0, winreg.REG_SZ, funcname)
        print(f"[+] Registered OID handler: {oid}")
        print(f"    Key: HKLM\\{path}")
        print(f"    Dll: {dll}")
        print(f"    FuncName: {funcname}")
    except PermissionError:
        print("error: access denied. Run as administrator.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"error: failed to register OID handler: {exc}", file=sys.stderr)
        sys.exit(1)


def clean_oid(winreg, oid: str) -> None:
    path = target_path(oid)
    wow64_flag = getattr(winreg, "KEY_WOW64_64KEY", 0)

    try:
        winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, path, wow64_flag, 0)
        print(f"[+] Removed OID handler: {oid}")
        print(f"    Key: HKLM\\{path}")
    except AttributeError:
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)
            print(f"[+] Removed OID handler: {oid}")
            print(f"    Key: HKLM\\{path}")
        except FileNotFoundError:
            print(f"[-] OID handler not found: {oid}")
        except PermissionError:
            print("error: access denied. Run as administrator.", file=sys.stderr)
            sys.exit(1)
        except OSError as exc:
            print(f"error: failed to remove OID handler: {exc}", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        print(f"[-] OID handler not found: {oid}")
    except PermissionError:
        print("error: access denied. Run as administrator.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"error: failed to remove OID handler: {exc}", file=sys.stderr)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Register or remove a CryptDllFormatObject OID handler."
    )
    parser.add_argument("--oid", required=True, help="OID to register or remove")
    parser.add_argument("--dll", help="Path to the formatter DLL")
    parser.add_argument(
        "--funcname",
        default="FormatObject",
        help="Exported formatter function name. Default: FormatObject",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove the OID handler instead of registering it",
    )
    args = parser.parse_args()

    if not args.clean and not args.dll:
        parser.error("--dll is required unless --clean is used")

    return args


def main() -> int:
    args = parse_args()
    require_windows()
    winreg = load_winreg()

    if args.clean:
        clean_oid(winreg, args.oid)
    else:
        register_oid(winreg, args.oid, args.dll, args.funcname)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
