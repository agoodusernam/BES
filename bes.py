import os
from copy import deepcopy
from typing import Union

from blocks import DataBlock, NonceBlock, TagBlock, KeyBlock
from errors import TagVerificationError
from utils import list_blocks_to_bytes


class BES:
    """
    The Bad Encryption Standard class for encryption and decryption

    :param key: The encryption key
    :param mode: The mode of operation. When in doubt, use "CTR" (Counter mode).

    :exception TagVerificationError: Raised when the tag does not match during decryption

    :returns: A cipher object that can be used to encrypt and decrypt data.
    """

    def __init__(self, key: str | bytes, mode: str = "CTR") -> None:
        self.data: str | bytes | int = 0
        self.MODE: str = mode
        self.VER: str = "0.7.1"

        self._key: str | bytes = key
        self._blocks: list[DataBlock] = []
        self._keyBlock: KeyBlock = KeyBlock(key)
        # you CAN set the rounds to any number if you really want to, but you probably shouldn't
        self._rounds: int = 30

    @property
    def key(self) -> str | bytes:
        return self._key

    @key.setter
    def key(self, key: str | bytes) -> None:
        self._key = key
        self._keyBlock: KeyBlock = KeyBlock(key)

    @property
    def rounds(self) -> int:
        return self._rounds

    @rounds.setter
    def rounds(self, rounds: int) -> None:
        self._rounds = rounds

    def encrypt(self, *, data: bytes | str, nonce: int | bytes = None) -> tuple[bytes, bytes, TagBlock]:
        """
        Encrypts the given data using the Bad Encryption Standard algorithm.

        :param data: The data to encrypt
        :param nonce: The nonce to use for encryption. If None, a random nonce will be generated.
        :return: A tuple containing the encrypted data blocks, the nonce used, and the tag block.
        """
        n: int = 4
        blocksize: int = n ** 2
        blocks: list[DataBlock] = []

        if isinstance(data, str):
            data = data.encode("utf-8")
        if isinstance(data, int):
            # Convert int data to minimally-sized big-endian bytes
            data = data.to_bytes((data.bit_length() + 7) // 8 or 1, byteorder="big")

        if isinstance(nonce, int):
            # Convert int nonce to exactly one block of bytes (big-endian)
            nonce = nonce.to_bytes(blocksize, byteorder="big", signed=False)

        if nonce is None:
            nonce = os.urandom(blocksize)

        # Ensure we only use one block worth of nonce bytes
        nonce_used = nonce[:blocksize]

        for chunk in range(0, len(data), blocksize):
            blocks.append(DataBlock(data[chunk:chunk + blocksize], n))

        key = deepcopy(self._keyBlock)

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

        return list_blocks_to_bytes(blocks), nonce_used, tag

    def decrypt(self,
                *,
                data: bytes | list[DataBlock],
                nonce: int | bytes,
                tag: TagBlock | bytes = None) -> bytes:
        """
        Decrypts the given data using the Bad Encryption Standard algorithm.
            :param data: The data to decrypt
            :param nonce: The nonce used for encryption. Must be the same as the one used during encryption.
            :param tag: The tag used for verification. None will skip verification.
            :return: The decrypted data as bytes.
        """
        key = deepcopy(self._keyBlock)

        # split the data into blocks
        blocksize: int = key.size ** 2
        blocks: list[DataBlock] = []
        if isinstance(data, bytes):
            for chunk in range(0, len(data), blocksize):
                blocks.append(DataBlock.from_bytes(data[chunk:chunk + blocksize], key.size))

        data = blocks

        if isinstance(tag, bytes):
            expectedTag: TagBlock = TagBlock(size=data[0].size)
            expectedTag(tag)
            toVerify = True

        elif isinstance(tag, TagBlock):
            expectedTag: TagBlock = deepcopy(tag)
            toVerify = True

        else:
            expectedTag = TagBlock()
            toVerify = False

        if isinstance(nonce, int):
            nonce = nonce.to_bytes(blocksize, byteorder="big", signed=False)
        if isinstance(nonce, bytes):
            nonce = nonce[:blocksize]
        nonceBlock = NonceBlock(nonce, size=key.size)
        result = []

        newTag: TagBlock = TagBlock(size=data[0].size)

        key.next()

        for block in data:
            decBlock: NonceBlock = nonceBlock
            if toVerify:
                newTag(decBlock)

            for _ in range(self._rounds):
                decBlock.apply_sbox()
                decBlock ^= key
                key.next()

            result.append(block ^ decBlock)

            # Always advance key once more after rounds, just like in encryption

            if toVerify:
                newTag(key)
                newTag.mix_rows()
                newTag.rotate_column(0, 1)
                newTag.rotate_column(1, 2)
                newTag.rotate_column(2, 3)
                newTag(block ^ decBlock)

            nonceBlock += 1

        if toVerify:
            if not expectedTag == newTag:
                # If the tags do not match, raise an error
                raise TagVerificationError("Tag mismatch! Decryption failed.")

        self.data = None
        self._blocks = None

        return b''.join(block.to_bytes() for block in result)

    # alias
    decrypt_and_verify = decrypt
