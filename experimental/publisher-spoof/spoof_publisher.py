#!/usr/bin/env python3
"""Generate a lab-only code-signing chain with a caller-controlled publisher CN."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def derived_path(path: Path, suffix: str) -> Path:
    return path.with_name(f"{path.stem}{suffix}")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a self-signed CA and code-signing leaf certificate for lab use."
    )
    parser.add_argument("--cn", required=True, help="Publisher name to embed in the certificate CN")
    parser.add_argument("--output-cert", required=True, help="Output path for the code-signing leaf certificate (PEM)")
    parser.add_argument("--output-key", required=True, help="Output path for the code-signing leaf private key (PEM)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if shutil.which("openssl") is None:
        print("error: openssl was not found in PATH", file=sys.stderr)
        return 1

    leaf_cert = Path(args.output_cert).expanduser().resolve()
    leaf_key = Path(args.output_key).expanduser().resolve()

    if leaf_cert == leaf_key:
        print("error: --output-cert and --output-key must be different paths", file=sys.stderr)
        return 1

    leaf_cert.parent.mkdir(parents=True, exist_ok=True)
    leaf_key.parent.mkdir(parents=True, exist_ok=True)

    root_cert = derived_path(leaf_cert, ".root.pem")
    root_key = derived_path(leaf_key, ".root.key")
    csr_path = derived_path(leaf_cert, ".csr")
    ext_path = derived_path(leaf_cert, ".codesign.ext")
    serial_path = derived_path(leaf_cert, ".root.srl")
    pfx_path = derived_path(leaf_cert, ".pfx")

    write_text(
        ext_path,
        "\n".join(
            [
                "basicConstraints=CA:FALSE",
                "keyUsage=digitalSignature",
                "extendedKeyUsage=codeSigning",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
                "",
            ]
        ),
    )

    try:
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-sha256",
                "-days",
                "3650",
                "-nodes",
                "-subj",
                f"/CN={args.cn}",
                "-keyout",
                str(root_key),
                "-out",
                str(root_cert),
            ]
        )
        run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:3072",
                "-nodes",
                "-subj",
                f"/CN={args.cn}",
                "-keyout",
                str(leaf_key),
                "-out",
                str(csr_path),
            ]
        )
        run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr_path),
                "-CA",
                str(root_cert),
                "-CAkey",
                str(root_key),
                "-CAcreateserial",
                "-CAserial",
                str(serial_path),
                "-out",
                str(leaf_cert),
                "-days",
                "825",
                "-sha256",
                "-extfile",
                str(ext_path),
            ]
        )
    except subprocess.CalledProcessError as exc:
        print(f"error: openssl failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode or 1
    finally:
        for scratch in (csr_path, ext_path, serial_path):
            if scratch.exists():
                scratch.unlink()

    print("Generated files:")
    print(f"  Root CA cert : {root_cert}")
    print(f"  Root CA key  : {root_key}")
    print(f"  Leaf cert    : {leaf_cert}")
    print(f"  Leaf key     : {leaf_key}")
    print()
    print("Next steps (manual only):")
    print("  1. Enroll the root CA into LocalMachine\\Root if the test box does not already trust it.")
    print("  2. Enroll the leaf certificate into LocalMachine\\TrustedPublisher.")
    print("  3. Sign a PE with the leaf certificate using osslsigncode or signtool.")
    print("  4. Enable the SIP hijack or FinalPolicy hijack path in your lab setup.")
    print("  5. Launch the PE and inspect the UAC dialog publisher string.")
    print()
    print("Windows import examples:")
    print(f"  certutil -addstore Root \"{root_cert}\"")
    print(f"  certutil -addstore TrustedPublisher \"{leaf_cert}\"")
    print()
    print("osslsigncode example:")
    print(
        f"  osslsigncode sign -certs \"{leaf_cert}\" -key \"{leaf_key}\" "
        "-n \"Lab build\" -in input.exe -out signed.exe"
    )
    print()
    print("signtool example (first package PEM material as a PFX):")
    print(
        f"  openssl pkcs12 -export -out \"{pfx_path}\" -inkey \"{leaf_key}\" "
        f"-in \"{leaf_cert}\" -certfile \"{root_cert}\""
    )
    print(f"  signtool sign /f \"{pfx_path}\" /fd SHA256 input.exe")
    print()
    print("Safety note: this script only generates certificates. It does not auto-enroll or auto-sign.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
