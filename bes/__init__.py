"""BES package

Public API: BES cipher, selected utility helpers, and error types.
Internal modules: bes.blocks and other non-exported helpers are considered internal.

Note: BES is experimental and intended for research/education only. Do not use in production.
"""

from .bes import BES
from .utils import (
    generate_nonce,
    blocks_to_bytes,
    to_b64,
    from_b64,
    derive_key_scrypt,
    as_bytes_utf8,
    bytes_to_str_utf8,
)
from .errors import (
    BESError,
    BlockSizeError,
    NonceOverflowError,
    NonceUnderflowError,
    TagVerificationError,
    KeyLengthError,
    NonceLengthError,
)

__all__ = [
    "BES",
    # helpers
    "generate_nonce",
    "blocks_to_bytes",
    "to_b64",
    "from_b64",
    "derive_key_scrypt",
    "as_bytes_utf8",
    "bytes_to_str_utf8",
    # errors
    "BESError",
    "BlockSizeError",
    "NonceOverflowError",
    "NonceUnderflowError",
    "TagVerificationError",
    "KeyLengthError",
    "NonceLengthError",
]