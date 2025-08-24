# BES

The Bad Encryption Standard (BES)

## IMPORTANT SECURITY DISCLAIMER
- BES is an experimental educational cipher. Do NOT use it to protect real data.
- There is no formal security proof. The algorithm, parameters, and implementation may contain weaknesses.
- Nonce reuse under the same key is dangerous. Always use a fresh, unique nonce per encryption.

## Overview
BES is a toy encryption scheme intended for learning and experimentation. It exposes a small Python API for encrypting/decrypting bytes and computing an authentication tag.

## Installation
- Development install: clone the repo and run `pip install -e .` (editable install). The package name is `bes`.
- Run examples: `python examples/basic_usage.py`
- CLI: after install, run `bes --help` for a demo command-line interface.

## Quickstart
- Encrypt/decrypt using the BES class. All inputs and outputs are bytes. Tag is returned as bytes by default.

## Example
```
from bes import BES
from bes import generate_nonce, to_hex

key = b"16ByteKey16Bytes"  # 16 bytes for n=4
bes = BES(key, rounds=30)

plaintext = b"Hello, World!"
# You can supply your own nonce; otherwise it will be generated internally
nonce = generate_nonce(size=4)
ciphertext, used_nonce, tag = bes.encrypt(data=plaintext, nonce=nonce)

print("ciphertext:", to_hex(ciphertext))

recovered = bes.decrypt(data=ciphertext, nonce=used_nonce, tag=tag)
print("recovered:", recovered)
```

## Utilities
- utils.generate_nonce(size): returns size*size bytes of randomness using os.urandom.
- utils.to_hex/from_hex, utils.to_b64/from_b64: safe helpers for serializing bytes.

## Notes
- Nonce uniqueness: never reuse a nonce with the same key. Prefer generate_nonce or a unique counter per session.
- Performance: rounds are configurable; see docs/plan.md for trade-offs.
- Benchmarks: see benchmarks/perf_test.py for CLI usage. Output goes to benchmarks/outputs.

## Roadmap
- See docs/plan.md and docs/tasks.md for the improvement plan and checklist.


## Public API & Module Boundaries
- Public (import from bes):
  - BES
  - Helpers: generate_nonce, blocks_to_bytes, to_hex/from_hex, to_b64/from_b64, derive_key_scrypt, as_bytes_utf8, bytes_to_str_utf8
  - Errors: BESError, BlockSizeError, NonceOverflowError, NonceUnderflowError, TagVerificationError, KeyLengthError, NonceLengthError
- Internal: bes.blocks and unlisted helpers are internal and subject to change.
- API types: BES(key: bytes), encrypt(data: bytes, nonce: Optional[bytes]) -> (ciphertext: bytes, nonce: bytes, tag: bytes). decrypt(data: bytes, nonce: bytes, tag: Optional[bytes]) -> bytes. TagBlock is deprecated in decrypt.

## CLI
- After installation, run `bes encrypt --help` or `bes decrypt --help`.
  - Uses Base64 for inputs/outputs.
  - You may derive a key from a passphrase and salt with scrypt via flags: `--passphrase` and `--salt-b64`. The derived key length is n^2 bytes.
