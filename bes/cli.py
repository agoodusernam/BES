"""Simple CLI for BES encryption/decryption with Base64 I/O.

Usage examples:
  # Encrypt (provide key as Base64, plaintext as Base64); outputs three lines: ciphertext_b64, nonce_b64, tag_b64
  bes encrypt --key-b64 MTZCeXRlS2V5MTZCeXRlcw== --data-b64 SGVsbG8sIEJFUyE=

  # Decrypt
  bes decrypt --key-b64 MTZCeXRlS2V5MTZCeXRlcw== --data-b64 <ct_b64> --nonce-b64 <nonce_b64> --tag-b64 <tag_b64>

  # Derive key from passphrase and salt using scrypt (n defaults to 4 -> 16 bytes key)
  bes encrypt --passphrase "p@ss" --salt-b64 c2FsdFNhbHQ= --data-b64 SGVsbG8=

Note: BES is experimental and not for production. See README.
"""
from __future__ import annotations

import sys
import argparse

from . import BES, to_b64, from_b64
from .utils import derive_key_scrypt


def _get_key(args: argparse.Namespace) -> bytes:
    if getattr(args, "key_b64", None):
        key = from_b64(args.key_b64)
        return key
    if getattr(args, "passphrase", None) is not None and getattr(args, "salt_b64", None) is not None:
        salt = from_b64(args.salt_b64)
        return derive_key_scrypt(args.passphrase, n=args.n, salt=salt)
    raise SystemExit("error: must provide either --key-b64 or both --passphrase and --salt-b64")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bes", description="BES demo CLI (Base64 I/O)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--n", type=int, default=4, help="Block size n (key length will be n^2 bytes); default 4")
    common.add_argument("--key-b64", type=str, help="Key bytes in Base64 (length must be n^2)")
    common.add_argument("--passphrase", type=str, help="Passphrase to derive a key (scrypt)")
    common.add_argument("--salt-b64", type=str, help="Salt for scrypt in Base64 (required with --passphrase)")

    enc = sub.add_parser("encrypt", parents=[common], help="Encrypt data (Base64 in/out)")
    enc.add_argument("--data-b64", type=str, required=True, help="Plaintext as Base64")
    enc.add_argument("--nonce-b64", type=str, help="Nonce in Base64 (optional); will be generated if omitted")

    dec = sub.add_parser("decrypt", parents=[common], help="Decrypt data (Base64 in/out)")
    dec.add_argument("--data-b64", type=str, required=True, help="Ciphertext as Base64")
    dec.add_argument("--nonce-b64", type=str, required=True, help="Nonce as Base64")
    dec.add_argument("--tag-b64", type=str, required=True, help="Authentication tag as Base64")

    return p


def cmd_encrypt(args: argparse.Namespace) -> int:
    key = _get_key(args)
    if len(key) != args.n * args.n:
        print(f"error: key must be exactly {args.n * args.n} bytes (n^2)", file=sys.stderr)
        return 2

    data = from_b64(args.data_b64)
    nonce: bytes | None
    nonce = from_b64(args.nonce_b64) if args.nonce_b64 else None

    bes = BES(key)
    ct, used_nonce, tag = bes.encrypt(data=data, nonce=nonce)
    print(to_b64(ct))
    print(to_b64(used_nonce))
    print(to_b64(tag))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    key = _get_key(args)
    if len(key) != args.n * args.n:
        print(f"error: key must be exactly {args.n * args.n} bytes (n^2)", file=sys.stderr)
        return 2

    data = from_b64(args.data_b64)
    nonce = from_b64(args.nonce_b64)
    tag = from_b64(args.tag_b64)

    bes = BES(key)
    pt = bes.decrypt(data=data, nonce=nonce, tag=tag)
    print(to_b64(pt))
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "encrypt":
            code = cmd_encrypt(args)
        elif args.cmd == "decrypt":
            code = cmd_decrypt(args)
        else:
            code = 2
    except Exception as e:  # surface as message with non-zero exit
        print(f"error: {e}", file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
