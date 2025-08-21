class BESError(Exception):
    """Base exception for BES encryption errors"""
    pass


class BlockSizeError(BESError):
    """Raised when block operations have a size mismatch"""
    pass


class NonceOverflowError(BESError):
    """Raised when nonce operations would cause overflow"""
    pass


class NonceUnderflowError(BESError):
    """Raised when nonce operations would cause overflow"""
    pass


class TagVerificationError(BESError):
    """Raised when tag verification fails during decryption"""
    pass


class KeyLengthError(BESError):
    """Raised when key has inappropriate length"""
    pass
