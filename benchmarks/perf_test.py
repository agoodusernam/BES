import argparse
import json
import math
import time
from pathlib import Path

# Allow running this script directly without installing the package
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from bes import BES
from bes.blocks import KeyBlock


def test_entropy(rounds: int = 15, size: int = 4) -> float:
    """Measure entropy of KeyBlock outputs."""
    import os

    key = KeyBlock(os.urandom(size * size), size)
    all_bytes: list[int] = []

    for _ in range(rounds):
        key.next()
        for i in range(size):
            for j in range(size):
                all_bytes.append(key.data[i][j])

    # Calculate byte frequencies
    freqs: dict[int, int] = {}
    for b in all_bytes:
        freqs[b] = freqs.get(b, 0) + 1

    # Calculate Shannon entropy
    total = len(all_bytes)
    entropy = 0.0
    for count in freqs.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def test_avalanche_effect(rounds: int = 15, size: int = 4) -> list[float]:
    """Test if changing one bit in input creates significant changes in output."""
    import os

    # Create two keys differing by one bit
    base_key = os.urandom(size * size)
    modified_key = bytearray(base_key)
    modified_key[0] ^= 1  # Flip lowest bit of first byte

    key1 = KeyBlock(base_key, size)
    key2 = KeyBlock(modified_key, size)

    # Track bit differences after each round
    results: list[float] = []
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

    return results


def run_benchmark(loops: int, rounds: int, data_size: int, runs_per_eta: int,
                  outputs_dir: Path) -> dict:
    import os

    print(f"Running performance test with {loops} loops of {data_size} bytes each with {rounds} rounds.")

    time_enc: list[float] = [0.0] * loops
    time_dec: list[float] = [0.0] * loops

    start_time: float = time.perf_counter()
    times: list[float | int] = [0] * 5

    for i in range(loops):
        data: bytes = os.urandom(data_size)
        now: float = time.perf_counter()
        cipher = BES(b"16ByteKey16Bytes", rounds=rounds)
        encdata, nonce, tag = cipher.encrypt(data=data)
        time_enc[i] = (time.perf_counter() - now) * 1000
        now = time.perf_counter()
        cipher.decrypt(data=encdata, nonce=nonce, tag=tag)
        time_dec[i] = (time.perf_counter() - now) * 1000

        if runs_per_eta > 0 and i % runs_per_eta == 0:
            now_time = time.perf_counter()
            percent = (i / loops) * 100

            if i > 0:
                print(f"Attempt {i}/{loops} ({percent:.2f}%)")
                elapsed = now_time - start_time
                times = [elapsed] + times[:-1]
                nonzero = list(filter(None, times))
                avg_time = sum(nonzero) / len(nonzero)
                remaining = (loops - i) / max(1, runs_per_eta) * avg_time
                print(f"ETA: {int(remaining / 60)} minutes, {int(remaining) % 60} seconds")

            start_time = now_time

    avg_enc = sum(time_enc) / max(1, loops)
    avg_dec = sum(time_dec) / max(1, loops)
    print(f"Average encryption time: {avg_enc:.3f} ms")
    print(f"Average decryption time: {avg_dec:.3f} ms")
    print(f"KiB/s: {data_size / (avg_enc / 1000) / 1024:.2f}")

    entropy = test_entropy(rounds)
    difference = test_avalanche_effect(rounds)
    print(f"Entropy: {entropy:.4f} bits (max for bytes is 8.0)")
    print(f"Average difference: {sum(difference) / len(difference):.2f}%")

    outputs_dir.mkdir(parents=True, exist_ok=True)
    results_path = outputs_dir / "results.json"

    # Initialize file if missing
    if not results_path.exists():
        with results_path.open("w", encoding="utf-8") as f:
            json.dump({
                "encryption_time": 0,
                "decryption_time": 0,
                "entropy": 0,
                "avalanche_effect": 0
            }, f, indent=4)

    with results_path.open("r", encoding="utf-8") as f:
        results = json.load(f)

    # Compare the results
    if results.get("encryption_time", 0) != 0:
        print(f"Encryption time difference: {avg_enc - results['encryption_time']:.3f} ms")
    if results.get("decryption_time", 0) != 0:
        print(f"Decryption time difference: {avg_dec - results['decryption_time']:.3f} ms")
    if results.get("entropy", 0) != 0:
        print(f"Entropy difference: {entropy - results['entropy']:.4f} bits")
    if results.get("avalanche_effect", 0) != 0:
        avg_diff = sum(difference) / len(difference)
        print(f"Avalanche effect difference: {avg_diff - results['avalanche_effect']:.2f}%")

    # Write new results
    with results_path.open("w", encoding="utf-8") as f:
        json.dump({
            "encryption_time": avg_enc,
            "decryption_time": avg_dec,
            "entropy": entropy,
            "avalanche_effect": sum(difference) / len(difference)
        }, f, indent=4)

    return {
        "avg_enc_ms": avg_enc,
        "avg_dec_ms": avg_dec,
        "entropy": entropy,
        "avg_avalanche_percent": sum(difference) / len(difference),
        "results_path": str(results_path)
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BES benchmark: encryption/decryption performance and characteristics")
    p.add_argument("--loops", type=int, default=10_000, help="Number of encryption/decryption loops")
    p.add_argument("--rounds", type=int, default=30, help="Number of rounds for BES")
    p.add_argument("--data-size", type=int, default=64, help="Random plaintext size in bytes per loop")
    p.add_argument("--runs-per-eta", type=int, default=100, help="How often to update ETA (in loops)")
    p.add_argument("--outputs-dir", type=str, default=str(Path(__file__).resolve().parent / "outputs"),
                   help="Directory to write results.json (default: benchmarks/outputs next to this script)")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    outputs_dir = Path(args.outputs_dir)

    run_benchmark(
        loops=args.loops,
        rounds=args.rounds,
        data_size=args.data_size,
        runs_per_eta=args.runs_per_eta,
        outputs_dir=outputs_dir,
    )


if __name__ == "__main__":
    main()
