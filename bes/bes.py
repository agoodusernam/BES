import os
import hmac
import logging

from .blocks import DataBlock, NonceBlock, TagBlock, KeyBlock
from .errors import TagVerificationError, NonceLengthError
from .utils import blocks_to_bytes

logger = logging.getLogger(__name__)


class BES:
    """
    The Bad Encryption Standard class for encryption and decryption

    :param key: The encryption key (bytes-like of length n^2; default n is 4 -> 16 bytes)
    :param mode: The mode of operation. When in doubt, use "CTR" (Counter mode).

    :exception TagVerificationError: Raised when the tag does not match during decryption
    :exception NonceLengthError: Raised when the provided nonce length is incorrect
    :exception TypeError: Raised when inputs are of incorrect type
    :exception ValueError: Raised when inputs have invalid values

    :returns: A cipher object that can be used to encrypt and decrypt data.
    """

    def __init__(self, key: bytes, mode: str = "CTR") -> None:
        self.data: bytes | None = None
        self.MODE: str = mode
        self.VER: str = "0.7.1"

        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be a bytes-like object")
        self._key: bytes = bytes(key)
        self._blocks: list[DataBlock] | None = None
        # Ensure KeyBlock is always built from bytes; KeyBlock will validate length exactly
        self._keyBlock: KeyBlock = KeyBlock(self._key)
        # you CAN set the rounds to any number if you really want to, but you probably shouldn't
        self._rounds: int = 30

    @property
    def key(self) -> bytes:
        return self._key

    @key.setter
    def key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be a bytes-like object")
        self._key = bytes(key)
        self._keyBlock = KeyBlock(self._key)


    def encrypt(self, *, data: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:
        """
        Encrypts the given data using the Bad Encryption Standard algorithm.
        
        :param data: The data to encrypt
        :param nonce: The nonce to use for encryption (bytes of length n^2). If None, a random nonce will be generated.
        :return: A tuple containing the encrypted data bytes, the nonce used (bytes), and the tag (bytes by default).
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be a bytes-like object")
        n: int = 4
        blocksize: int = n ** 2
        blocks: list[DataBlock] = []

        data = bytes(data)

        if nonce is None:
            nonce = os.urandom(blocksize)
        elif isinstance(nonce, (bytes, bytearray, memoryview)):
            nonce = bytes(nonce)
            if len(nonce) != blocksize:
                raise NonceLengthError(f"Nonce must be exactly {blocksize} bytes long, got {len(nonce)}")
        else:
            raise TypeError("nonce must be None or bytes-like")

        # Use exactly one block worth of nonce bytes
        nonce_used = nonce

        for chunk in range(0, len(data), blocksize):
            blocks.append(DataBlock(data[chunk:chunk + blocksize], n))

        # Build a fresh KeyBlock from the raw key bytes (cheaper than deepcopy)
        key_src = self._key if isinstance(self._key, (bytes, bytearray, memoryview)) else str(self._key).encode("utf-8")
        key = KeyBlock(bytes(key_src))

        nonceBlock: NonceBlock = NonceBlock(nonce_used, size=n)
        tag: TagBlock = TagBlock(size=n)

        key.next()

        for block in blocks:
            encBlock: NonceBlock = nonceBlock
            tag(encBlock)
            for _ in range(self._rounds):
                encBlock.apply_sbox()
                encBlock ^= key

                key.next()

            block ^= encBlock
            tag(key)
            tag.mix_rows()
            tag.rotate_column(0, 1)
            tag.rotate_column(1, 2)
            tag.rotate_column(2, 3)
            tag(block ^ encBlock)
            nonceBlock += 1

        self.data = None
        self._blocks = None

        return blocks_to_bytes(blocks), nonce_used, bytes(tag)

    def decrypt(self,
                *,
                data: bytes,
                nonce: bytes,
                tag: bytes | None = None) -> bytes:
        """
        Decrypts the given data using the Bad Encryption Standard algorithm.
            :param data: The data to decrypt (bytes only)
            :param nonce: The nonce used for encryption (bytes of length n^2). Must match encryption.
            :param tag: The tag used for verification as bytes. None skips verification. TagBlock is deprecated.
            :return: The decrypted data as bytes.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be a bytes-like object")
        data = bytes(data)

        # Build a fresh KeyBlock from the raw key bytes
        key = KeyBlock(self._key)

        # split the data into blocks
        blocksize: int = key.size ** 2
        blocks: list[DataBlock] = []
        for chunk in range(0, len(data), blocksize):
            blocks.append(DataBlock.from_bytes(data[chunk:chunk + blocksize], key.size))

        # Tag handling
        toVerify: bool
        if isinstance(tag, (bytes, bytearray, memoryview)):
            expectedTag: TagBlock = TagBlock(size=key.size)
            expectedTag(bytes(tag))
            toVerify = True

        elif tag is None:
            expectedTag = TagBlock(size=key.size)
            toVerify = False
        else:
            raise TypeError("tag must be bytes-like, or None")

        # Nonce handling
        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            raise TypeError("nonce must be a bytes-like object")
        nonce = bytes(nonce)
        if len(nonce) != blocksize:
            raise NonceLengthError(f"Nonce must be exactly {blocksize} bytes long, got {len(nonce)}")

        nonceBlock = NonceBlock(nonce, size=key.size)
        result: list[DataBlock] = []

        newTag: TagBlock = TagBlock(size=key.size)

        key.next()

        for block in blocks:
            decBlock: NonceBlock = nonceBlock
            if toVerify:
                newTag(decBlock)

            for _ in range(self._rounds):
                decBlock.apply_sbox()
                decBlock ^= key
                key.next()

            result.append(block ^ decBlock)

            if toVerify:
                newTag(key)
                newTag.mix_rows()
                newTag.rotate_column(0, 1)
                newTag.rotate_column(1, 2)
                newTag.rotate_column(2, 3)
                newTag(block ^ decBlock)

            nonceBlock += 1

        if toVerify:
            expected_bytes = bytes(expectedTag)
            new_bytes = bytes(newTag)
            if not hmac.compare_digest(expected_bytes, new_bytes):
                raise TagVerificationError("Tag mismatch! Decryption failed.")

        self.data = None
        self._blocks = None

        return b''.join(block.to_bytes() for block in result)

    # alias
    decrypt_and_verify = decrypt
