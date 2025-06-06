import unittest
from main import Block

class TestBlock(unittest.TestCase):
	def test_rotateRow_rotates_right_correctly(self):
		"""
		[1, 2, 3, 4]
		[5, 6, 7, 8]
		[9, 10, 11, 12]
		[13, 14, 15, 16]

		"""
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		block.rotate_row(0, 1)
		block.rotate_row(1, 2)
		block.rotate_row(2, 3)
		self.assertEqual(block[0], [4, 1, 2, 3])
		self.assertEqual(block[1], [7, 8, 5, 6])
		self.assertEqual(block[2], [10, 11, 12, 9])
		self.assertEqual(block[3], [13, 14, 15, 16])


	def test_rotateRow_rotates_left_correctly(self):
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		block.rotate_row(0, -1)
		block.rotate_row(1, -2)
		block.rotate_row(2, -3)
		self.assertEqual(block[0], [2, 3, 4, 1])
		self.assertEqual(block[1], [7, 8, 5, 6])
		self.assertEqual(block[2], [12, 9, 10, 11])
		self.assertEqual(block[3], [13, 14, 15, 16])

	def test_rotateRow_handles_large_amounts(self):
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		block.rotate_row(0, 5)
		block.rotate_row(1, 6)
		block.rotate_row(2, 7)
		self.assertEqual(block[0], [4, 1, 2, 3])
		self.assertEqual(block[1], [7, 8, 5, 6])
		self.assertEqual(block[2], [10, 11, 12, 9])
		self.assertEqual(block[3], [13, 14, 15, 16])


	def test_rotateColumn_rotates_down_correctly(self):
		"""
		[1, 2, 3, 4]
		[5, 6, 7, 8]
		[9, 10, 11, 12]
		[13, 14, 15, 16]
		"""
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		block.rotate_column(0, 1)
		block.rotate_column(1, 2)
		block.rotate_column(2, 3)
		self.assertEqual([block[i][0] for i in range(4)], [13, 1, 5, 9])
		self.assertEqual([block[i][1] for i in range(4)], [10, 14, 2, 6])
		self.assertEqual([block[i][2] for i in range(4)], [7, 11, 15, 3])
		self.assertEqual(block[3], [9, 6, 3, 16])


	def test_rotateColumn_rotates_up_correctly(self):
		"""
		[1, 2, 3, 4]
		[5, 6, 7, 8]
		[9, 10, 11, 12]
		[13, 14, 15, 16]
		"""
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		block.rotate_column(0, -1)
		block.rotate_column(1, -2)
		block.rotate_column(2, -3)
		self.assertEqual([block[i][0] for i in range(4)], [5, 9, 13, 1])
		self.assertEqual([block[i][1] for i in range(4)], [10, 14, 2, 6])
		self.assertEqual([block[i][2] for i in range(4)], [15, 3, 7, 11])
		self.assertEqual(block[3], [1, 6, 11, 16])


	def test_rotateColumn_handles_large_amounts(self):
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		block.rotate_column(0, 5)
		block.rotate_column(1, 6)
		block.rotate_column(2, 7)
		self.assertEqual([block[i][0] for i in range(4)], [13, 1, 5, 9])
		self.assertEqual([block[i][1] for i in range(4)], [10, 14, 2, 6])
		self.assertEqual([block[i][2] for i in range(4)], [7, 11, 15, 3])
		self.assertEqual(block[3], [9, 6, 3, 16])

	def test_byte_conversion(self):
		block = Block([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]])
		self.assertEqual(block.to_bytes(), b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10')

		self.assertEqual(Block.from_bytes(block.to_bytes()), block)


if __name__ == '__main__':
	unittest.main()
