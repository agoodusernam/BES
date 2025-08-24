from __future__ import annotations

import copy
import operator
import os
import logging
from typing import Self, Generator, Any

from .errors import BlockSizeError, NonceOverflowError, NonceUnderflowError, KeyLengthError
from .constants import SBOX as SBOX_TABLE, ROUND_CONSTANTS as RCON

logger = logging.getLogger(__name__)


class Block:
    """
	This class represents a cryptographic block that uses substitution-permutation
	networks (SPN). The block contains predefined substitution boxes (S-Box) and their
	inverse (Inverse S-Box) for symmetric encryption and decryption operations, designed
	to implement a secure and efficient transformation of data.

	Attributes:
		data (list[list[int]]): The data contained in the block, represented as a 2D list.
		size (int): The size of the block (number of rows/columns).
		_round (int): The current round number in the encryption/decryption process.

	"""
    SBOX = SBOX_TABLE
    
    def __init__(self, data: list[list[int]], size: int = 4) -> None:
        # Validate shape and byte range
        if not isinstance(data, list) or len(data) != size or any(not isinstance(row, list) or len(row) != size for row in data):
            raise BlockSizeError("Data must be a 2D list with shape size x size")
        for i in range(size):
            for j in range(size):
                v = data[i][j]
                if not isinstance(v, int) or not (0 <= v <= 255):
                    raise ValueError("Block values must be integers in range 0..255")
        self.data: list[list[int]] = data
        self.size: int = size
        self._round: int = 0
    
    def __repr__(self) -> tuple[str, int, int]:
        return str(self.data), self.size, self._round
    
    def __str__(self) -> str:
        return "\n".join(str(row) for row in self.data) + "\n"
    
    def __getitem__(self, item) -> list[int]:
        return self.data[item]
    
    def __setitem__(self, key: int, value: list[int]) -> None:
        self.data[key] = value
    
    def __eq__(self, other: Block) -> bool:
        # noinspection PyUnreachableCode
        if not isinstance(other, Block):
            # I have no idea why PyCharm thinks this is unreachable, it is not
            raise TypeError(f"Other must be Block or Block subclass, got {type(other).__name__} instead")
        if self.size != other.size:
            return False
        return all(self.data[i][j] == other.data[i][j]
                   for i in range(self.size)
                   for j in range(self.size))
    
    
    def __deepcopy__(self, memo: dict[int, Any] = None) -> Self:
        """Create a deep copy of the Block."""
        if memo is None:
            memo = {}
        
        # Create deep copies of the nested lists
        data_copy = copy.deepcopy(self.data, memo)
        
        return self.from_2d_array(data_copy, self.size)
    
    __copy__ = __deepcopy__
    
    def __xor__(self, other: Block) -> Self:
        if not isinstance(other, Block):
            raise TypeError(f"Other must be Block or Block subclass, got {type(other).__name__} instead")
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to XOR")
        
        # Use map with operator.xor for faster operations
        result_data = [list(map(operator.xor, self_row, other_row))
                       for self_row, other_row in zip(self.data, other.data)]
        
        return self.from_2d_array(result_data, self.size)
    
    def __ixor__(self, other: Block) -> Self:
        if not isinstance(other, Block):
            raise TypeError(f"Other must be Block or Block subclass, got {type(other).__name__} instead")
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to XOR")
        
        for i, (self_row, other_row) in enumerate(zip(self.data, other.data)):
            self.data[i] = list(map(operator.xor, self_row, other_row))
        
        return self
    
    def __len__(self) -> int:
        return self.size ** 2
    
    def __iter__(self) -> Generator[list[int], None, None]:
        # Iterate over the block
        for row in self.data:
            yield row
    
    def __bytes__(self) -> bytes:
        # Faster and less allocation-heavy than repeated concatenation
        return b"".join(bytes(row) for row in self.data)
    
    to_bytes = __bytes__
    
    def __and__(self, other: Block) -> Self:
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to AND")
        
        result_data = [[self.data[i][j] & other.data[i][j]
                        for j in range(self.size)]
                       for i in range(self.size)]
        
        return self.from_2d_array(result_data, self.size)
    
    def __iand__(self, other: Block) -> Self:
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to AND")
        
        for i in range(self.size):
            for j in range(self.size):
                self.data[i][j] &= other.data[i][j]
        return self
    
    def __or__(self, other: Block) -> Self:
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to OR")
        
        result_data = [[self.data[i][j] | other.data[i][j]
                        for j in range(self.size)]
                       for i in range(self.size)]
        
        return self.from_2d_array(result_data, self.size)
    
    def __ior__(self, other: "Block") -> Self:
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to OR")
        
        for i in range(self.size):
            for j in range(self.size):
                self.data[i][j] |= other.data[i][j]
        return self
    
    def get_column(self, column: int) -> list[int]:
        # Get the column from the block
        return [self.data[i][column] for i in range(self.size)]
    
    def set_column(self, column: int, data: list[int]) -> None:
        # Set the column in the block
        if len(data) != self.size:
            raise BlockSizeError("Data length must match block size")
        for i in range(self.size):
            self.data[i][column] = data[i]
    
    def rotate_row(self, row: int, amount: int) -> None:
        amount = amount % self.size
        
        if amount != 0:
            row_data = self.data[row]
            if amount > 0:
                # Rotate right
                self.data[row] = row_data[-amount:] + row_data[:-amount]
            else:
                # Rotate left
                amount = abs(amount)
                self.data[row] = row_data[amount:] + row_data[:amount]
    
    def rotate_column(self, column: int, amount: int) -> None:
        amount = amount % self.size
        
        if amount != 0:
            column_data = [self.data[j][column] for j in range(self.size)]
            
            if amount > 0:
                rotated = column_data[-amount:] + column_data[:-amount]
            else:
                amount = abs(amount)
                rotated = column_data[amount:] + column_data[:amount]
            
            # Update the column in the data
            for j in range(self.size):
                self.data[j][column] = rotated[j]
    
    def mix_columns(self) -> "Block":
        for col in range(self.size):
            column = self.get_column(col)
            mixed = [0] * self.size
            for i in range(self.size):
                mixed[i] = column[(i + 1) % self.size] ^ (column[i] << 1) ^ column[(i - 1) % self.size]
            
            for i in range(self.size):
                self.data[i][col] = mixed[i] & 0xFF
        return self
    
    def mix_rows(self) -> "Block":
        for row in range(self.size):
            mixed = [0] * self.size
            for i in range(self.size):
                mixed[i] = (self.data[row][(i + 1) % self.size] ^ (self.data[row][i] << 1) ^ self.data[row][(i - 1) %
                                                                                                            self.size]) % 0xFF
            
            self.data[row] = mixed
        return self
    
    @classmethod
    def from_bytes(cls, data: bytes, size: int = 4) -> "Block":
        """Create a block from bytes."""
        if len(data) > size * size:
            data = data[:size * size]
        elif len(data) < size * size:
            data = data + b'\x00' * (size * size - len(data))
        
        block_data = [[0] * size for _ in range(size)]
        for i in range(size):
            for j in range(size):
                idx = i * size + j
                if idx < len(data):
                    block_data[i][j] = data[idx]
        return cls(block_data, size)
    
    @classmethod
    def from_2d_array(cls, data: list[list[int]], size: int = 4) -> "Block":
        """Create a new instance of this class from a 2D array of data
        Validates shape (size x size) and byte range [0..255].
        """
        if not isinstance(data, list) or len(data) != size or any(not isinstance(row, list) or len(row) != size for row in data):
            raise BlockSizeError("Data must be a 2D list with shape size x size")
        for i in range(size):
            for j in range(size):
                v = data[i][j]
                if not isinstance(v, int) or not (0 <= v <= 255):
                    raise ValueError("Block values must be integers in range 0..255")
        return cls([list(row) for row in data], size=size)
    
    def apply_sbox(self) -> Self:
        for i in range(self.size):
            for j in range(self.size):
                self.data[i][j] = self.SBOX[self.data[i][j]]
        return self


class KeyBlock(Block):
    ROUND_CONSTANTS: tuple[int, ...] = RCON
    
    def __init__(self, key: bytes, size: int = 4) -> None:
        # Initialize with empty data
        super().__init__([[0] * size for _ in range(size)], size)

        # Validate key type and exact length policy (Task #9)
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be a bytes-like object")
        key_bytes = bytes(key)
        required_len = self.size ** 2
        if len(key_bytes) != required_len:
            raise KeyLengthError(f"Key must be exactly {required_len} bytes long")
        
        self.__RCONBLOCKS: list[Block] = []
        
        for i in range(size ** 2):
            # Create a slice that wraps around using modulo
            constants = [self.ROUND_CONSTANTS[(i + j) % len(self.ROUND_CONSTANTS)] for j in range(self.size)]
            self.__RCONBLOCKS.append(Block([constants] * self.size, self.size))
        
        # Fill the key material exactly
        for i, byte in enumerate(key_bytes):
            row = i // self.size
            col = i % self.size
            self.data[row][col] = byte
        
    def __next__(self) -> KeyBlock:
        self._round += 1
        self.apply_sbox()
        self.__ixor__(self.__RCONBLOCKS[(self._round - 1) % len(self.__RCONBLOCKS)])
        
        if self._round % 2 == 0:
            for i in range(1, self.size):
                self.rotate_row(i - 1, i)
                self.rotate_column(self.size - i, i)
        else:
            for i in range(1, self.size):
                self.rotate_row(self.size - i, i)
                self.rotate_column(i - 1, i)
        
        self.mix_columns()
        self.mix_rows()
        
        return self
    
    next = __next__
    
    @classmethod
    def from_2d_array(cls, data: list[list[int]], size: int = 4) -> "KeyBlock":
        """Create a new KeyBlock from a 2D array"""
        flat_data = bytes(item for row in data for item in row)
        return cls(flat_data, size)
    
    @classmethod
    def from_str(cls, text: str, size: int = 4) -> "KeyBlock":
        """Create a block from a string."""
        return cls(text.encode('utf-8'), size)


class DataBlock(Block):
    
    def __init__(self, data: bytes, size: int = 4) -> None:
        # Initialize with empty data
        super().__init__([[0] * size for _ in range(size)], size)
        # Track how many bytes in this block are meaningful (for partial last blocks)
        self._valid_length: int = min(len(data), self.size ** 2)
        
        if self._valid_length:
            mv = memoryview(data)[:self._valid_length]
            full_rows, rem = divmod(self._valid_length, self.size)
            # Copy full rows
            for r in range(full_rows):
                start = r * self.size
                end = start + self.size
                self.data[r] = list(mv[start:end])
            # Copy remaining bytes into the next row
            if rem:
                r = full_rows
                for c, b in enumerate(mv[full_rows * self.size: full_rows * self.size + rem]):
                    self.data[r][c] = b
    
    def to_bytes(self) -> bytes:
        """
        Return exactly the original number of bytes stored in this block (no PKCS#7 trimming).
        """
        raw_bytes = bytes(item for row in self.data for item in row)
        return raw_bytes[:getattr(self, "_valid_length", self.size ** 2)]
    
    # Ensure XOR operations respect the valid length (only XOR meaningful bytes)
    def __ixor__(self, other: Block) -> DataBlock:
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to XOR")
        valid_length = getattr(self, "_valid_length", self.size ** 2)
        full_rows, rem = divmod(valid_length, self.size)
        for r in range(full_rows):
            self.data[r] = list(map(operator.xor, self.data[r], other.data[r]))
        # Handle remaining bytes in the next row, if any
        if rem:
            r = full_rows
            for c in range(rem):
                self.data[r][c] ^= other.data[r][c]
        return self
    
    def __xor__(self, other: Block) -> DataBlock:
        if self.size != other.size:
            raise BlockSizeError("Blocks must be the same size to XOR")
        # Start from a copy that preserves the valid length and contents
        result = DataBlock(self.to_bytes(), self.size)
        result ^= other
        return result
        
    @classmethod
    def from_bytes(cls, data: bytes, size: int = 4) -> DataBlock:
        """
        Create a DataBlock directly from raw bytes.
        Overrides the Block.from_bytes to avoid passing a list into __init__.
        """
        return cls(data, size)
    
    
    @classmethod
    def from_str(cls, text: str, size: int = 4) -> DataBlock:
        """Create a block from a string."""
        return cls(text.encode('utf-8'), size)
    
    @classmethod
    def from_2d_array(cls, data: list[list[int]], size: int = 4) -> DataBlock:
        # Validate using Block's rules
        _ = Block.from_2d_array(data, size)  # will raise on invalid shape/value range
        flat_data = bytes(item for row in data for item in row)
        return cls(flat_data, size)


# noinspection DuplicatedCode
class NonceBlock(Block):
    # Maximum value before overflow (all bytes set to maximum)
    OVERFLOW_THRESHOLD = (2 ** 8) ** (4 * 4) - 1  # For a 4x4 block, all bytes at 0xFF
    
    def __init__(self, nonce: bytes | int, size: int = 4) -> None:
        # Initialize with a proper 2D array structure
        super().__init__([[0] * size for _ in range(size)], size)
        if nonce is None:
            nonce = os.urandom(size * size)
        
        # Convert int to bytes if needed
        if isinstance(nonce, int):
            nonce = nonce.to_bytes(size * size, byteorder='big')
        
        # Fill the structure with bytes
        for i in range(min(len(nonce), size * size)):
            row = i // size
            col = i % size
            self.data[row][col] = nonce[i]
    
    def _add_to_nonce(self, other: int) -> None:
        """Helper method to handle nonce addition directly in the block data structure"""
        if other <= 0:
            return
        
        # For small increments (typically 1), find the first non-0xFF byte and increment it
        # Working from right to left (least significant to most significant)
        for i in range(self.size - 1, -1, -1):
            for j in range(self.size - 1, -1, -1):
                if self.data[i][j] < 0xFF:
                    # Found a byte we can increment without overflow
                    self.data[i][j] += 1
                    return
                else:
                    # Reset this byte and continue to the next one (carry)
                    self.data[i][j] = 0
        
        # If we got here, all bytes were 0xFF and were reset to 0
        raise NonceOverflowError("Nonce addition would overflow")
    
    def __add__(self, other: int) -> NonceBlock:
        """Create a new NonceBlock with the added value"""
        result = copy.deepcopy(self)
        result._add_to_nonce(other)
        return result
    
    def __iadd__(self, other: int) -> NonceBlock:
        """Add to this NonceBlock in-place"""
        self._add_to_nonce(other)
        return self
    
    def _sub_from_nonce(self, other: int) -> bytes:
        """Helper method to handle nonce subtraction and return the resulting bytes"""
        # Convert the entire block to an integer
        data_bytes = self.to_bytes()
        data_int = int.from_bytes(data_bytes, byteorder='big')
        
        # Check for underflow
        if data_int < other:
            raise NonceUnderflowError("Nonce subtraction would underflow")
        
        data_int -= other
        # Convert back to bytes with proper padding
        return data_int.to_bytes(self.size * self.size, byteorder='big')
    
    def __sub__(self, other: int) -> NonceBlock:
        """Create a new NonceBlock with the subtracted value"""
        new_bytes = self._sub_from_nonce(other)
        return NonceBlock(new_bytes, self.size)
    
    def __isub__(self, other: int) -> NonceBlock:
        """Subtract from this NonceBlock in-place"""
        new_bytes = self._sub_from_nonce(other)
        
        # Update the block data with new bytes
        for i in range(len(new_bytes)):
            row = i // self.size
            col = i % self.size
            if row < self.size and col < self.size:
                self.data[row][col] = new_bytes[i]
        return self


class TagBlock(Block):
    """
	TagBlock class for storing and manipulating tag data
	"""
    
    def __init__(self, size: int = 4) -> None:
        # Initialize with empty data
        super().__init__([[0] * size for _ in range(size)], size)
    
    def __call__(self, block: Block | bytes) -> None:
        # Apply the tag to the block
        if isinstance(block, bytes):
            block = Block.from_bytes(block)
        for i in range(self.size):
            for j in range(self.size):
                self.data[i][j] ^= block.data[i][j]

    def __eq__(self, other: Block) -> bool:
        # Compare based on bytes representation only to avoid structure-based equality
        if not isinstance(other, Block):
            raise TypeError(f"Other must be Block or Block subclass, got {type(other).__name__} instead")
        return bytes(self) == bytes(other)
    
    @classmethod
    def from_2d_array(cls, data: list[list[int]], size: int = 4) -> TagBlock:
        new_Block = TagBlock(size)
        # Validate and convert input data into a proper Block using the provided size
        validated_block = Block.from_2d_array(data, size)
        new_Block(validated_block)
        return new_Block
