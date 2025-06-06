import secrets


def minCycleLength(sbox: list[int]) -> int:
	smallest = 2**16-1
	for i in range(len(sbox)):
		count = 0
		value = i
		while True:
			count += 1
			value = sbox[value]
			if value == i:
				break
		if count < smallest:
			smallest = count

	return smallest

def inverseSBox(sbox: list[int]) -> list[int]:
	inverse = [0] * len(sbox)
	for i in range(len(sbox)):
		inverse[sbox[i]] = i
	return inverse

def main() -> list[int] | None:
	numBits = 8
	numValues = 2 ** numBits
	sbox = [0] * numValues
	avaliableValues = [x for x in range(numValues)]
	for i in range(numValues):
		choice = avaliableValues.index(secrets.choice(avaliableValues))
		sbox[i] = avaliableValues[choice]
		avaliableValues.pop(choice)

	# ensure all values are unique
	if len(set(sbox)) != numValues:
		return None

	# ensure no value maps to itself
	for i in range(numValues):
		if sbox[i] == i:
			return None

	# ensure no value maps to itself after 2 iterations
	for i in range(numValues):
		if sbox[i] == sbox[sbox[i]]:
			return None


	return sbox

if __name__ == '__main__':
	sbox = None
	minCycle = 127
	cycleLength = 0
	while (sbox is None) or (cycleLength < minCycle):
		sbox = main()
		if sbox is not None:
			cycleLength = minCycleLength(sbox)

	print(cycleLength)
	print(sbox)

	print(inverseSBox(sbox))

