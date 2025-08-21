import os
import time
import math
import json

from bes import BES
from blocks import KeyBlock


def main() -> None:
    rounds: int = 30
    dataAmountBytes: int = 64
    numLoops: int = 10_000
    runsPerETA: int = 100
    
    times: list[float | int] = [0] * 5
    timeEnc: list[float] = [0.0] * numLoops
    timeDec: list[float] = [0.0] * numLoops
    print(f"Running performance test with {numLoops} loops of {dataAmountBytes} bytes each with {rounds} rounds.")
    
    start_time: float = time.perf_counter()
    for i in range(numLoops):
        data: bytes = os.urandom(dataAmountBytes)
        now: float = time.perf_counter()
        cipher = BES(b"16ByteKey16Bytes")
        encdata, nonce, tag = cipher.encrypt(data=data)
        timeEnc[i] = (time.perf_counter() - now) * 1000
        now = time.perf_counter()
        cipher.decrypt(data=encdata, nonce=nonce, tag=tag)
        timeDec[i] = (time.perf_counter() - now) * 1000
        if i % runsPerETA == 0:
            nowTime = time.perf_counter()
            percent = (i / numLoops) * 100
            
            if i > 0:
                print(f"Attempt {i}/{numLoops} ({percent:.2f}%)")
                elapsed = nowTime - start_time
                times = [elapsed] + times[:-1]
                avgTime = sum(filter(None, times)) / len(list(filter(None, times)))
                remaining = (numLoops - i) / runsPerETA * avgTime
                print(f"ETA: {int(remaining / 60)} minutes, {int(remaining) % 60} seconds")
            
            start_time = nowTime
    
    avgEnc = sum(timeEnc) / numLoops
    avgDec = sum(timeDec) / numLoops
    print(f"Average encryption time: {avgEnc:.3f} ms")
    print(f"Average decryption time: {avgDec:.3f} ms")
    print(f"KiB/s: {dataAmountBytes / (avgEnc / 1000) / 1024:.2f}")
    
    entropy = test_entropy(rounds)
    difference = test_avalanche_effect(rounds)
    print(f"Entropy: {entropy:.4f} bits (max for bytes is 8.0)")
    print(f"Average difference: {sum(difference) / len(difference):.2f}%")
    
    # compare results and show the difference
    # read the results from the file
    # if file does not exist, create it
    if not os.path.exists("results.json"):
        with open("results.json", "w") as f:
            json.dump({
                "encryption_time":  0,
                "decryption_time":  0,
                "entropy":          0,
                "avalanche_effect": 0
            }, f, indent=4)
    with open("results.json", "r") as f:
        results = json.load(f)
    
    # compare the results
    if results["encryption_time"] != 0:
        print(f"Encryption time difference: {avgEnc - results['encryption_time']:.3f} ms")
    if results["decryption_time"] != 0:
        print(f"Decryption time difference: {avgDec - results['decryption_time']:.3f} ms")
    if results["entropy"] != 0:
        print(f"Entropy difference: {entropy - results['entropy']:.4f} bits")
    if results["avalanche_effect"] != 0:
        print(f"Avalanche effect difference: {sum(difference) / len(difference) - results['avalanche_effect']:.2f}%")
    # compare the results and show the difference
    
    # write results to file
    # if file exists, delete it and create a new one
    if os.path.exists("results.json"):
        os.remove("results.json")
    
    with open("results.json", "w") as f:
        json.dump({
            "encryption_time":  avgEnc,
            "decryption_time":  avgDec,
            "entropy":          entropy,
            "avalanche_effect": sum(difference) / len(difference)
        }, f, indent=4)


def test_entropy(rounds=15, size=4):
    """Measure entropy of KeyBlock outputs."""
    
    key = KeyBlock(os.urandom(size * size), size)
    all_bytes = []
    
    for _ in range(rounds):
        key.next()
        for i in range(size):
            for j in range(size):
                all_bytes.append(key.data[i][j])
    
    # Calculate byte frequencies
    freqs = {}
    for b in all_bytes:
        freqs[b] = freqs.get(b, 0) + 1
    
    # Calculate Shannon entropy
    total = len(all_bytes)
    entropy = 0
    for count in freqs.values():
        p = count / total
        entropy -= p * math.log2(p)
    
    # print(f"Entropy: {entropy:.4f} bits (max for bytes is 8.0)")
    return entropy


def test_avalanche_effect(rounds=15, size=4) -> list[float]:
    """Test if changing one bit in input creates significant changes in output."""
    # Create two keys differing by one bit
    base_key = os.urandom(size * size)
    modified_key = bytearray(base_key)
    modified_key[0] ^= 1  # Flip lowest bit of first byte
    
    key1 = KeyBlock(base_key, size)
    key2 = KeyBlock(modified_key, size)
    
    # Track bit differences after each round
    results = []
    for _ in range(rounds):
        key1.next()
        key2.next()
        
        # Count bit differences between keys
        diff_bits = 0
        total_bits = size * size * 8
        
        for i in range(size):
            for j in range(size):
                xor_val = key1.data[i][j] ^ key2.data[i][j]
                diff_bits += bin(xor_val).count('1')
        
        percent_diff = (diff_bits / total_bits) * 100
        results.append(percent_diff)
    # print(f"Round {_ + 1}: {diff_bits}/{total_bits} bits differ ({percent_diff:.2f}%)")
    
    # Ideally should approach 50% difference
    return results


if __name__ == "__main__":
    main()
