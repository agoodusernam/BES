import warnings
import base64
import binascii
import os
from collections.abc import Iterable
import hashlib
from .blocks import Block


def blocks_to_bytes(blocks: Iterable[Block]) -> bytes:
    """Concatenate the bytes of each Block in the iterable.

    Args:
        blocks: Any iterable of Block instances.

    Returns:
        A single bytes object formed by concatenating Block.to_bytes() for each element.

    Raises:
        TypeError: If any element is not a Block (index included in message).
    """
    parts: list[bytes] = []
    for i, block in enumerate(blocks):
        if not isinstance(block, Block):
            raise TypeError(f"blocks[{i}] expected Block, got {type(block).__name__}")
        parts.append(block.to_bytes())
    return b"".join(parts)


def generate_nonce(size: int = 4) -> bytes:
    """Generate a random nonce of exactly size*size bytes using os.urandom.

    Note: Nonce reuse is dangerous. Ensure a unique nonce per encryption under the same key.

    Args:
        size: Block dimension (n); nonce length will be n*n bytes. Defaults to 4.

    Returns:
        Random bytes of length size*size.
    """
    if not isinstance(size, int) or size < 1:
        raise ValueError("size must be a positive integer")
    return os.urandom(size * size)


def to_b64(data: bytes) -> str:
    """Encode bytes as standard Base64 string without newlines."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("to_b64 expects a bytes-like object")
    return base64.b64encode(bytes(data)).decode("ascii")


def from_b64(text: str) -> bytes:
    """Decode a Base64 string to bytes."""
    if not isinstance(text, str):
        raise TypeError("from_b64 expects a str")
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid base64 string: {e}") from e



def derive_key_scrypt(passphrase: str | bytes, n: int = 4, salt: bytes = b"", *, N: int = 2**14, r: int = 8, p: int = 1) -> bytes:
    """Derive a fixed-size key of length n^2 bytes using scrypt.

    Args:
        passphrase: The passphrase as str (UTF-8) or bytes.
        n: Block dimension; output length is n*n bytes (default 4 -> 16 bytes).
        salt: Required salt as bytes. Must be non-empty and unique per user/context.
        N, r, p: scrypt work-factor parameters.

    Returns:
        Derived key bytes of length n^2.

    Raises:
        TypeError/ValueError on invalid inputs.
    """
    if not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive integer")
    if not isinstance(salt, (bytes, bytearray, memoryview)) or len(salt) == 0:
        raise ValueError("salt must be a non-empty bytes-like object")
    pwd = passphrase.encode("utf-8") if isinstance(passphrase, str) else bytes(passphrase)
    length = n * n
    return hashlib.scrypt(pwd, salt=bytes(salt), n=N, r=r, p=p, dklen=length)


def as_bytes_utf8(value: bytes | str) -> bytes:
    """Convenience wrapper: convert str to UTF-8 bytes; passthrough bytes-like."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("expected bytes-like or str")


def bytes_to_str_utf8(data: bytes | bytearray | memoryview) -> str:
    """Convenience wrapper: decode bytes to UTF-8 string with strict errors."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("expected bytes-like object")
    return bytes(data).decode("utf-8")
