import copy
import operator
import os
import time
from copy import deepcopy
from typing import Self, Generator, Union


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
	SBOX = [
		0x52, 0xE5, 0x21, 0x66, 0x2A, 0x68, 0x57, 0xEF, 0x23, 0xBA, 0xDC, 0x77, 0x4F, 0x51, 0x49, 0x45, 0xBD, 0xB4,
		0x82, 0xB8, 0x94, 0x9C, 0xA0, 0xAE, 0x09, 0x85, 0x5B, 0x39, 0x8D, 0x7D, 0x59, 0xDF, 0x55, 0x35, 0xE1, 0xF1,
		0x9A, 0x3C, 0xC9, 0x1B, 0x3B, 0x78, 0xEA, 0x06, 0x29, 0x46, 0x10, 0xBF, 0xDE, 0xE7, 0xC2, 0x31, 0xFB, 0x89,
		0x88, 0x4E, 0x62, 0x6B, 0x75, 0xE4, 0x0D, 0x08, 0xEB, 0x30, 0x02, 0xA1, 0x48, 0x12, 0xC6, 0x98, 0xB3, 0xF4,
		0x16, 0x92, 0xB2, 0x6C, 0x86, 0x22, 0x1D, 0x54, 0x8F, 0xFA, 0x3A, 0x1F, 0x81, 0xD7, 0xE0, 0x26, 0xE3, 0xDD,
		0xB0, 0x83, 0xF8, 0x37, 0x7B, 0xE9, 0x7C, 0x9F, 0xF0, 0xED, 0x8A, 0x5D, 0x56, 0x53, 0xE8, 0xD3, 0x72, 0x2D,
		0xBE, 0xAD, 0xFE, 0xEE, 0x60, 0x4D, 0x33, 0x93, 0x99, 0x41, 0xD0, 0x65, 0x74, 0xC4, 0xB5, 0x9B, 0xE2, 0x05,
		0xB7, 0x5C, 0xAC, 0xCA, 0x69, 0xFD, 0xB6, 0x0E, 0xA5, 0x17, 0x13, 0x7F, 0xCE, 0x87, 0x00, 0x80, 0x0C, 0x27,
		0x04, 0x58, 0xC8, 0x0A, 0xD8, 0x15, 0x63, 0xCB, 0xAA, 0x8E, 0x25, 0x1A, 0x6E, 0xC1, 0x8B, 0xAF, 0x76, 0xD5,
		0xDA, 0x0B, 0x2B, 0x28, 0x19, 0xAB, 0x90, 0x5A, 0x1E, 0x6F, 0xA3, 0x0F, 0x3E, 0x3F, 0xB1, 0xF2, 0x9D, 0xC3,
		0xF5, 0xB9, 0x5E, 0xF7, 0x11, 0xFC, 0x43, 0x7E, 0x38, 0x42, 0x6A, 0xE6, 0x95, 0xC0, 0xCF, 0x1C, 0xCD, 0x7A,
		0x36, 0x73, 0xD9, 0x14, 0xBB, 0x4B, 0x4C, 0xA7, 0x91, 0xA8, 0x24, 0xA4, 0x40, 0xF3, 0x61, 0xF6, 0x71, 0x32,
		0x8C, 0x67, 0x70, 0x4A, 0x2C, 0x79, 0x5F, 0x34, 0xD6, 0x01, 0x47, 0x2E, 0xC7, 0xD1, 0x97, 0x3D, 0xDB, 0x18,
		0x50, 0xD2, 0x44, 0xFF, 0xF9, 0x64, 0x9E, 0x03, 0xCC, 0x2F, 0xD4, 0xBC, 0x6D, 0x07, 0x20, 0xC5, 0x84, 0x96,
		0xA9, 0xA6, 0xA2, 0xEC]

	def __init__(self, data: list[list[int]], size: int = 4) -> None:
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

	def __eq__(self, other: "Block") -> bool:
		if not isinstance(other, Block):
			raise TypeError(f"Other must be Block or Block subclass, got {type(other).__name__} instead")
		if self.size != other.size:
			return False
		return all(self.data[i][j] == other.data[i][j]
				   for i in range(self.size)
				   for j in range(self.size))

	def __copy__(self) -> Self:
		# Create a shallow copy of the data structure (new lists, same integer values)
		data_copy = [list(row) for row in self.data]

		# Use from_2d_array to ensure correct class type is returned
		new_instance = self.from_2d_array(data_copy, self.size)

		# Copy additional attributes if needed
		new_instance._round = self._round

		return new_instance

	def __deepcopy__(self, memo: dict = None) -> Self:
		"""Create a deep copy of the Block."""
		if memo is None:
			memo = {}

		# Create deep copies of the nested lists
		data_copy = copy.deepcopy(self.data, memo)

		return self.from_2d_array(data_copy, self.size)

	def __xor__(self, other: "Block") -> Self:
		if self.size != other.size:
			raise BlockSizeError("Blocks must be the same size to XOR")

		# Use map with operator.xor for faster operations
		result_data = [list(map(operator.xor, self_row, other_row))
					   for self_row, other_row in zip(self.data, other.data)]

		return self.from_2d_array(result_data, self.size)

	def __ixor__(self, other: "Block") -> Self:
		if self.size != other.size:
			raise BlockSizeError("Blocks must be the same size to XOR")

		for i, (self_row, other_row) in enumerate(zip(self.data, other.data)):
			self.data[i] = list(map(operator.xor, self_row, other_row))

		return self

	def __len__(self) -> int:
		return self.size ** 2

	def __iter__(self) -> Generator[list[int]]:
		# Iterate over the block
		for row in self.data:
			yield row

	def __bytes__(self) -> bytes:
		byte_format = bytes()
		for i in self.data:
			byte_format += bytes(i)

		return byte_format

	to_bytes = __bytes__

	def __contains__(self, item: int | list[int] | bytes) -> bool:

		if isinstance(item, list):
			for row in self.data:
				if item == row:
					return True
			return False

		if isinstance(item, int):
			for row in self.data:
				if item in row:
					return True
			return False

		if isinstance(item, bytes):
			for row in self.data:
				rowBytes = [bytes(item) for item in row]
				if item in rowBytes:
					return True
			return False

		raise TypeError(f"Expected item to be int, list[int], or bytes, got {type(item).__name__} instead")

	def __and__(self, other: "Block") -> Self:
		if self.size != other.size:
			raise BlockSizeError("Blocks must be the same size to AND")

		result_data = [[self.data[i][j] & other.data[i][j]
						for j in range(self.size)]
					   for i in range(self.size)]

		return self.from_2d_array(result_data, self.size)

	def __iand__(self, other: "Block") -> Self:
		if self.size != other.size:
			raise BlockSizeError("Blocks must be the same size to AND")

		for i in range(self.size):
			for j in range(self.size):
				self.data[i][j] &= other.data[i][j]
		return self

	def __or__(self, other: "Block") -> Self:
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
			raise ValueError("Data length must match block size")
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
		"""Create a new instance of this class from a 2D array of data"""
		print(size)
		return cls(data, size = size)

	def apply_sbox(self) -> Self:
		for i in range(self.size):
			for j in range(self.size):
				self.data[i][j] = self.SBOX[self.data[i][j]]
		return self


class KeyBlock(Block):
	ROUND_CONSTANTS: list[int] = [0x9b, 0x40, 0xb7, 0x1e, 0x1b, 0x4e, 0x68, 0x9e, 0xbe, 0x42, 0x76, 0xc2, 0xdc, 0x30,
								  0x4b, 0x17]

	def __init__(self, key: bytes, size: int = 4) -> None:
		# Initialize with empty data
		super().__init__([[0] * size for _ in range(size)], size)

		self.__RCONBLOCKS: list[Block] = []

		for i in range(size ** 2):
			# Create a slice that wraps around using modulo
			constants = [self.ROUND_CONSTANTS[(i + j) % len(self.ROUND_CONSTANTS)] for j in range(self.size)]
			self.__RCONBLOCKS.append(Block([constants] * self.size, self.size))

		for i, byte in enumerate(key):
			if i > self.size ** 2:
				raise KeyLengthError(f"Key must be at most {self.size ** 2} bytes long")
			row = i // self.size
			col = i % self.size
			self.data[row][col] = byte

	def __next__(self) -> "KeyBlock":
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

		# Calculate required size and padding
		required_bytes = self.size ** 2
		padding_length = required_bytes - min(required_bytes, len(data))

		# Apply PKCS#7 padding (padding bytes are filled with padding length value)
		if padding_length > 0:
			# Add padding bytes to the data
			padded_data = data + bytes([padding_length]) * padding_length
		else:
			padded_data = data[:required_bytes]

		# Process data into the block
		for i in range(min(len(padded_data), required_bytes)):
			row = i // self.size
			col = i % self.size
			self.data[row][col] = padded_data[i]

	def to_bytes(self) -> bytes:
		"""
		Extract data from the DataBlock and remove padding.
		Returns the original data as bytes.
		"""
		raw_bytes = bytes(item for row in self.data for item in row)

		if raw_bytes:
			padding_value = raw_bytes[-1]
			if 0 < padding_value <= self.size ** 2:
				if all(b == padding_value for b in raw_bytes[-padding_value:]):
					return raw_bytes[:-padding_value]

		return raw_bytes

	@classmethod
	def from_str(cls, text: str, size: int = 4) -> "DataBlock":
		"""Create a block from a string."""
		return cls(text.encode('utf-8'), size)

	@classmethod
	def from_2d_array(cls, data: list[list[int]], size: int = 4) -> "DataBlock":

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
			nonce = nonce.to_bytes(size * size, byteorder = 'big')

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

	def __add__(self, other: int) -> "NonceBlock":
		"""Create a new NonceBlock with the added value"""
		result = copy.deepcopy(self)
		result._add_to_nonce(other)
		return result

	def __iadd__(self, other: int) -> "NonceBlock":
		"""Add to this NonceBlock in-place"""
		self._add_to_nonce(other)
		return self

	def _sub_from_nonce(self, other: int) -> bytes:
		"""Helper method to handle nonce subtraction and return the resulting bytes"""
		# Convert the entire block to an integer
		data_bytes = self.to_bytes()
		data_int = int.from_bytes(data_bytes, byteorder = 'big')

		# Check for underflow
		if data_int < other:
			raise NonceUnderflowError("Nonce subtraction would underflow")

		data_int -= other
		# Convert back to bytes with proper padding
		return data_int.to_bytes(self.size * self.size, byteorder = 'big')

	def __sub__(self, other: int) -> "NonceBlock":
		"""Create a new NonceBlock with the subtracted value"""
		new_bytes = self._sub_from_nonce(other)
		return NonceBlock(new_bytes, self.size)

	def __isub__(self, other: int) -> "NonceBlock":
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

	def __call__(self, block: Union["Block", bytes]) -> None:
		# Apply the tag to the block
		if isinstance(block, bytes):
			block = Block.from_bytes(block)
		for i in range(self.size):
			for j in range(self.size):
				self.data[i][j] ^= block.data[i][j]

	@classmethod
	def from_2d_array(cls, data: list[list[int]], size: int = 4) -> "TagBlock":

		new_Block = TagBlock(size)
		new_Block(Block(data))
		return new_Block



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
			data = data.to_bytes()

		if isinstance(nonce, int):
			nonce: bytes = nonce.to_bytes()

		if nonce is None:
			nonce: bytes = os.urandom(blocksize)

		for chunk in range(0, len(data), blocksize):
			blocks.append(DataBlock(data[chunk:chunk + blocksize], n))

		key = deepcopy(self._keyBlock)

		nonceBlock: NonceBlock = NonceBlock(nonce[:16], size = n)
		tag: TagBlock = TagBlock(size = n)

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

		return list_blocks_to_bytes(blocks), nonce, tag


	def decrypt(self, *, data: bytes | list[DataBlock], nonce: int | bytes, tag: TagBlock | bytes = None) -> bytes:
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
			expectedTag: TagBlock = TagBlock(size = data[0].size)
			expectedTag(tag)
			toVerify = True

		elif isinstance(tag, TagBlock):
			expectedTag: TagBlock = deepcopy(tag)
			toVerify = True

		else:
			expectedTag = TagBlock()
			toVerify = False

		if isinstance(nonce, int):
			nonce = nonce.to_bytes()

		if len(nonce) > 16:
			nonce = nonce[:16]
		nonceBlock = NonceBlock(nonce, size = data[0].size)
		result = []

		newTag: TagBlock = TagBlock(size = data[0].size)

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

	decrypt_and_verify = decrypt

def list_blocks_to_bytes(blocks: list[DataBlock]) -> bytes:
	"""Convert a list of DataBlock objects to bytes."""
	for block in blocks:
		if not isinstance(block, Block):
			raise TypeError(f"Expected DataBlock, got {type(block).__name__}")
	return b''.join(block.to_bytes() for block in blocks)


def main() -> None:
	data = b'\x9dm\xe9\xc3\x11\xf0\x83[\xc3\x9b\x0f.\xee\r\x01Zq=\xb5\x90\x0b>\xb9Z!\xfa8\x19\xdb\xcb\xc7\xb0'
	nonce = b'\xfaZ\xca\x08\xf4\xd1\x03A\x1f\x80\xf8=uSY\xe6'
	key = b"16ByteKey16Bytes"

	cipher = BES(key)
	cipher._rounds = 5
	encdata, nonce, tag = cipher.encrypt(data = data, nonce = nonce)
	decryptedData = cipher.decrypt(data = encdata, nonce = nonce)

	if decryptedData != data:
		print("Decryption failed!")
		time.sleep(0.5)
		print("Decrypted Data:", decryptedData)
		print("Decrypted Data Block:\n", DataBlock(decryptedData))
		print("Original Data:", data)
		print("Original Data Block:\n", DataBlock(data))

	else:
		print("Decryption successful!")


if __name__ == '__main__':
	main()
