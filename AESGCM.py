from functools import reduce

import pyaes


def xor(x, y):
	"""Returns the exclusive or (xor) between two vectors"""
	return bytes(i ^ j for i, j in zip(x, y))


def intToList(number, listSize):
	"""Convert a number into a byte list"""
	return [(number >> i) & 0xff
			for i in reversed(range(0, listSize * 8, 8))]


def listToInt(list):
	"""Convert a byte list into a number"""
	return reduce(lambda x, y: (x << 8) + y, list)


def GHASH(hkey, aad, ctext):
	"""GCM's GHASH function"""

	def xorMultH(p, q):
		"""Multiply (p^q) by hash key"""

		def multGF2(x, y):
			"""Multiply two polynomials in GF(2^m)/g(w)
			   g(w) = w^128 + w^7 + w^2 + w + 1
			   (operands and result bits reflected)"""
			(x, y) = map(lambda z: listToInt(list(z)), (x, y))
			z = 0
			while y & ((1 << 128) - 1):
				if y & (1 << 127):
					z ^= x
				y <<= 1
				if x & 1:
					x = (x >> 1) ^ (0xe1 << 120)
				else:
					x >>= 1
			return bytes(intToList(z, 16))

		return bytes(multGF2(hkey, xor(p, q)))

	def gLen(s):
		"""Evaluate length of input in bits and returns
		   it in the LSB bytes of a 64-bit string"""
		return bytes(intToList(len(s) * 8, 8))

	x = bytes(16)
	aadP = aad + bytes((16 - len(aad) % 16) % 16)
	ctextP = ctext + bytes((16 - len(ctext) % 16) % 16)
	for i in range(0, len(aadP), 16):
		x = xorMultH(x, aadP[i:i + 16])
	for i in range(0, len(ctextP), 16):
		x = xorMultH(x, ctextP[i:i + 16])
	return xorMultH(x, gLen(aad) + gLen(ctext))


def GCM_crypt(key, iv, input, aad):
	"""GCM's Authenticated Encryption/Decryption Operations"""

	def incr(m):
		"""Increment the LSB 32 bits of input counter"""
		n = list(m)
		n12 = bytes(n[:12])
		ctr = listToInt(n[12:])
		if ctr == (1 << 32) - 1:
			return n12 + bytes(4)
		else:
			return n12 + bytes(intToList(ctr + 1, 4))

	obj = pyaes.AESModeOfOperationECB(key)
	h = bytes(obj.encrypt(bytes(16)))
	output = bytes()
	L = len(input)
	if len(iv) == 12:
		y0 = bytes(iv) + bytes(b'\x00\x00\x00\x01')
	else:
		y0 = bytes(GHASH(h, bytes(), iv))
	y = y0
	for i in range(0, len(input), 16):
		y = incr(y)
		ctextBlock = xor(bytes(obj.encrypt(y)),
						 input[i:min(i + 16, L)])
		output += bytes(ctextBlock)
	g = obj.encrypt(y0)
	tag = xor(GHASH(h, aad, output), g)
	return output, tag, g, h


def GCM_encrypt(keysize, key, iv, ptext, aad):
	"""GCM's Authenticated Encryption Operation"""
	(ctext, tag, g, h) = GCM_crypt(keysize, key, iv, ptext, aad)
	return ctext, xor(GHASH(h, aad, ctext), g)


def GCM_decrypt(keysize, key, iv, ctext, aad, tag):
	"""GCM's Authenticated Decryption Operation"""
	(ptext, _, g, h) = GCM_crypt(keysize, key, iv, ctext, aad)
	if tag == xor(GHASH(h, aad, ctext), g):
		return True, ptext
	else:
		return False, None


######################## Testing section ########################

if __name__ == '__main__':

	def printHex(s):
		"""Prints a bytes string in hex format"""
		print('{0:#0x}'.format(bytesToInt(s)))


	def bytesToInt(b):
		"""Converts a bytes string into an integer"""
		return listToInt(list(b))


	def listToInt(list):
		"""Convert a byte list into a number"""
		return reduce(lambda x, y: (x << 8) + y, list)


	def checkTestVector(id, keysize, key, ptext, aad, iv, ctext, tag):
		def intToBytes(n):
			"""Converts an integer into a bytes string"""
			lst = []
			while n:
				lst.append(n & 0xff)
				n >>= 8
			return bytes(reversed(lst))

		def convertType(v):
			"""Convert input variable type to bytes"""
			if type(v) is int:
				return intToBytes(v)
			elif type(v) is bytes:
				return v
			else:
				return bytes(v, 'ISO-8859-1')

		def printOutputs():
			"""Prints expected/evaluated tags and
					  expected/evaluated ciphertexts"""
			print("Tag expected:  ", end = "")
			printHex(tag)
			print("Tag evaluated: ", end = "")
			printHex(TAG)
			print("Ciphertext expected:  ", end = "")
			printHex(ctext)
			print("Ciphertext evaluated: ", end = "")
			printHex(CTEXT)

		(ptext, aad, iv, ctext, tag) = map(convertType, (ptext, aad, iv, ctext, tag))
		(CTEXT, TAG) = GCM_encrypt(keysize, key, iv, ptext, aad)
		(SUCCESS, PTEXT) = GCM_decrypt(keysize, key, iv, CTEXT, aad, TAG)

		try:
			assert SUCCESS & (CTEXT == ctext) & (TAG == tag)
			print("Test case {0:0d} succeeded".format(id))
		except AssertionError:
			print("Test case {0:0d} failed".format(id))
			printOutputs()

		# Test cases extracted from


	# "The Galois/Counter Mode of Operation(GCM)", McGrew & Viega, 2005 (http://goo.gl/DWJPK)

	# Some useful constants
	emptyString = bytes()  # zero length bit string
	nullBitString128 = bytes(16)  # 128-bit null string
	nullBitString96 = bytes(12)  # 96-bit null IV

	# Test Case #1
	testcase1 = {'id':  1, 'keysize': "SIZE_128", 'key': 0x0, 'ptext': emptyString,
				 'aad': emptyString, 'iv': nullBitString96, 'ctext': emptyString,
				 'tag': 0x58e2fccefa7e3061367f1d57a4e7455a}

	# Test Case #2
	testcase2 = {'id':  2, 'keysize': "SIZE_128", 'key': 0x0, 'ptext': nullBitString128,
				 'aad': emptyString, 'iv': nullBitString96, 'ctext': 0x0388dace60b6a392f328c2b971b2fe78,
				 'tag': 0xab6e47d42cec13bdf53a67b21257bddf}

	# Test Case #3
	testcase3 = {'id':    3, 'keysize': "SIZE_128", 'key': 0xfeffe9928665731c6d6a8f9467308308,
				 'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255,
				 'aad':   emptyString, 'iv': 0xcafebabefacedbaddecaf888,
				 'ctext': 0x42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985,
				 'tag':   0x4d5c2af327cd64a62cf35abd2ba6fab4}

	## Test Case #4
	testcase4 = {'id':    4, 'keysize': "SIZE_128", 'key': 0xfeffe9928665731c6d6a8f9467308308,
				 'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				 'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2, 'iv': 0xcafebabefacedbaddecaf888,
				 'ctext': 0x42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091,
				 'tag':   0x5bc94fbc3221a5db94fae95ae7121a47}

	## Test Case #5
	testcase5 = {'id':    5, 'keysize': "SIZE_128", 'key': 0xfeffe9928665731c6d6a8f9467308308,
				 'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				 'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2, 'iv': 0xcafebabefacedbad,
				 'ctext': 0x61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598,
				 'tag':   0x3612d2e79e3b0785561be14aaca2fccb}

	## Test Case #6
	testcase6 = {'id':    6, 'keysize': "SIZE_128", 'key': 0xfeffe9928665731c6d6a8f9467308308,
				 'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				 'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2,
				 'iv':    0x09313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b,
				 'ctext': 0x8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5,
				 'tag':   0x619cc5aefffe0bfa462af43c1699d050}

	## Test Case #7
	testcase7 = {'id':  7, 'keysize': "SIZE_192", 'key': 0x0, 'ptext': emptyString,
				 'aad': emptyString, 'iv': nullBitString96, 'ctext': emptyString,
				 'tag': 0xcd33b28ac773f74ba00ed1f312572435}

	## Test Case #8
	testcase8 = {'id':    8, 'keysize': "SIZE_192", 'key': 0x0, 'ptext': nullBitString128,
				 'aad':   emptyString, 'iv': nullBitString96,
				 'ctext': 0x98e7247c07f0fe411c267e4384b0f600,
				 'tag':   0x2ff58d80033927ab8ef4d4587514f0fb}

	## Test Case #9
	testcase9 = {'id':    9, 'keysize': "SIZE_192", 'key': 0xfeffe9928665731c6d6a8f9467308308feffe9928665731c,
				 'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255,
				 'aad':   emptyString, 'iv': 0xcafebabefacedbaddecaf888,
				 'ctext': 0x3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256,
				 'tag':   0x9924a7c8587336bfb118024db8674a14}

	## Test Case #10
	testcase10 = {'id':    10, 'keysize': "SIZE_192", 'key': 0xfeffe9928665731c6d6a8f9467308308feffe9928665731c,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				  'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2, 'iv': 0xcafebabefacedbaddecaf888,
				  'ctext': 0x3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710,
				  'tag':   0x2519498e80f1478f37ba55bd6d27618c}

	## Test Case #11
	testcase11 = {'id':    11, 'keysize': "SIZE_192", 'key': 0xfeffe9928665731c6d6a8f9467308308feffe9928665731c,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				  'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2, 'iv': 0xcafebabefacedbad,
				  'ctext': 0x0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7,
				  'tag':   0x65dcc57fcf623a24094fcca40d3533f8}

	## Test Case #12
	testcase12 = {'id':    12, 'keysize': "SIZE_192", 'key': 0xfeffe9928665731c6d6a8f9467308308feffe9928665731c,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				  'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2,
				  'iv':    0x9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b,
				  'ctext': 0xd27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b,
				  'tag':   0xdcf566ff291c25bbb8568fc3d376a6d9}

	## Test Case #13
	testcase13 = {'id':  13, 'keysize': "SIZE_256", 'key': 0x0, 'ptext': emptyString,
				  'aad': emptyString, 'iv': nullBitString96, 'ctext': emptyString,
				  'tag': 0x530f8afbc74536b9a963b4f1c4cb738b}

	## Test Case #14
	testcase14 = {'id':  14, 'keysize': "SIZE_256", 'key': 0x0, 'ptext': nullBitString128,
				  'aad': emptyString, 'iv': nullBitString96, 'ctext': 0xcea7403d4d606b6e074ec5d3baf39d18,
				  'tag': 0xd0d1c8a799996bf0265b98b5d48ab919}

	## Test Case #15
	testcase15 = {'id':    15, 'keysize': "SIZE_256",
				  'key':   0xfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255,
				  'aad':   emptyString, 'iv': 0xcafebabefacedbaddecaf888,
				  'ctext': 0x522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad,
				  'tag':   0xb094dac5d93471bdec1a502270e3cc6c}

	## Test Case #16
	testcase16 = {'id':    16, 'keysize': "SIZE_256",
				  'key':   0xfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				  'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2, 'iv': 0xcafebabefacedbaddecaf888,
				  'ctext': 0x522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662,
				  'tag':   0x76fc6ece0f4e1768cddf8853bb2d551b}

	## Test Case #17
	testcase17 = {'id':    17, 'keysize': "SIZE_256",
				  'key':   0xfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				  'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2, 'iv': 0xcafebabefacedbad,
				  'ctext': 0xc3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f,
				  'tag':   0x3a337dbf46a792c45e454913fe2ea8f2}

	## Test Case #18
	testcase18 = {'id':    18, 'keysize': "SIZE_256",
				  'key':   0xfeffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308,
				  'ptext': 0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,
				  'aad':   0xfeedfacedeadbeeffeedfacedeadbeefabaddad2,
				  'iv':    0x9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b,
				  'ctext': 0x5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f,
				  'tag':   0xa44a8266ee1c8eb0c8b5d4cf5ae9f19a}

	for i in range(1, 19):
		checkTestVector(**(eval("testcase" + str(i))))