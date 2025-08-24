"""
BES Performance Benchmark

Methodology:
- Measures average encryption/decryption time over configurable loops and data size.
- Reports throughput (KiB/s), key schedule entropy proxy, and avalanche effect proxy.
- Captures environment metadata (Python version, platform, CPU count, params).
- Writes timestamped JSON outputs to benchmarks/outputs and also updates latest.json.

Reproduction:
- Example: python benchmarks/perf_test.py --loops 1000 --data-size 1024 --runs-per-eta 100 --reuse-cipher
- Optional: set BES_USE_NUMPY=1 to enable NumPy-accelerated S-Box application if numpy is installed.
"""
import argparse
import json
import math
import time
from pathlib import Path
import platform
import os
from datetime import datetime

# Allow running this script directly without installing the package
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from bes import BES
from bes.blocks import KeyBlock


def test_entropy(size: int = 4) -> float:
    """Measure entropy of KeyBlock outputs."""
    import os

    key = KeyBlock(os.urandom(size * size), size)
    all_bytes: list[int] = []

    for _ in range(30):
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


def test_avalanche_effect(size: int = 4) -> list[float]:
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
    for _ in range(30):
        key1.next()
        key2.next()

        # Count bit differences between keys
        diff_bits = 0
        total_bits = size * size * 8

        for i in range(size):
            for j in range(size):
                xor_val = key1.data[i][j] ^ key2.data[i][j]
                diff_bits += xor_val.bit_count()

        percent_diff = (diff_bits / total_bits) * 100
        results.append(percent_diff)

    return results


def run_benchmark(loops: int, data_size: int, runs_per_eta: int,
                  outputs_dir: Path, reuse_cipher: bool = False) -> dict:
    print(f"Running performance test with {loops} loops of {data_size} bytes each. Reuse cipher: {reuse_cipher}")

    time_enc: list[float] = [0.0] * loops
    time_dec: list[float] = [0.0] * loops

    # Prepare cipher if reusing
    cipher: BES | None = BES(b"16ByteKey16Bytes") if reuse_cipher else None

    wall_start_dt = datetime.now()
    wall_start: float = time.perf_counter()
    times: list[float | int] = [0] * 5

    for i in range(loops):
        data: bytes = os.urandom(data_size)
        now: float = time.perf_counter()
        ciph = cipher if cipher is not None else BES(b"16ByteKey16Bytes")
        encdata, nonce, tag = ciph.encrypt(data=data)
        time_enc[i] = (time.perf_counter() - now) * 1000
        now = time.perf_counter()
        ciph.decrypt(data=encdata, nonce=nonce, tag=tag)
        time_dec[i] = (time.perf_counter() - now) * 1000

        if runs_per_eta > 0 and i % runs_per_eta == 0:
            now_time = time.perf_counter()
            percent = (i / loops) * 100

            if i > 0:
                print(f"Attempt {i}/{loops} ({percent:.2f}%)")
                elapsed = now_time - wall_start
                times = [elapsed] + times[:-1]
                nonzero = list(filter(None, times))
                avg_time = sum(nonzero) / len(nonzero)
                remaining = (loops - i) / max(1, runs_per_eta) * avg_time
                print(f"ETA: {int(remaining / 60)} minutes, {int(remaining) % 60} seconds")

            wall_start = now_time

    avg_enc = sum(time_enc) / max(1, loops)
    avg_dec = sum(time_dec) / max(1, loops)
    kib_s = data_size / (avg_enc / 1000) / 1024 if avg_enc > 0 else float('inf')
    print(f"Average encryption time: {avg_enc:.3f} ms")
    print(f"Average decryption time: {avg_dec:.3f} ms")
    print(f"KiB/s: {kib_s:.2f}")

    entropy = test_entropy()
    difference = test_avalanche_effect()
    print(f"Entropy: {entropy:.4f} bits (max for bytes is 8.0)")
    avg_diff = sum(difference) / len(difference) if difference else 0.0
    print(f"Average difference: {avg_diff:.2f}%")

    outputs_dir.mkdir(parents=True, exist_ok=True)
    latest_path = outputs_dir / "latest.json"

    # Load previous latest for diff (if any)
    prev = None
    if latest_path.exists():
        try:
            with latest_path.open("r", encoding="utf-8") as f:
                prev = json.load(f)
        except Exception:
            prev = None

    # Build results with metadata
    use_numpy = str(os.getenv("BES_USE_NUMPY", "")).lower() in ("1", "true", "yes", "on")
    meta = {
        "timestamp": wall_start_dt.isoformat(timespec="seconds"),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "os": os.name,
        "cpu_count": os.cpu_count(),
        "params": {
            "loops": loops,
            "data_size": data_size,
            "runs_per_eta": runs_per_eta,
            "reuse_cipher": reuse_cipher,
            "use_numpy": use_numpy,
        },
    }

    results = {
        "metrics": {
            "avg_enc_ms": avg_enc,
            "avg_dec_ms": avg_dec,
            "throughput_kib_s": kib_s,
            "entropy": entropy,
            "avg_avalanche_percent": avg_diff,
        },
        "meta": meta,
    }

    # Write timestamped and latest files
    ts_name = datetime.now().strftime("results_%Y%m%d_%H%M%S.json")
    ts_path = outputs_dir / ts_name
    with ts_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    with latest_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Print diffs relative to previous latest
    if prev and isinstance(prev, dict):
        pmet = prev.get("metrics", {})
        nmet = results["metrics"]
        for key in ("avg_enc_ms", "avg_dec_ms", "entropy", "avg_avalanche_percent", "throughput_kib_s"):
            if key in pmet and isinstance(pmet[key], (int, float)):
                delta = nmet.get(key, 0) - pmet[key]
                print(f"{key} change: {delta:+.3f}")

    return {
        "results_path": str(ts_path),
        "latest_path": str(latest_path),
        **results,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BES benchmark: encryption/decryption performance and characteristics")
    p.add_argument("--loops", type=int, default=10_000, help="Number of encryption/decryption loops")
    p.add_argument("--data-size", type=int, default=64, help="Random plaintext size in bytes per loop")
    p.add_argument("--runs-per-eta", type=int, default=100, help="How often to update ETA (in loops)")
    p.add_argument("--outputs-dir", type=str, default=str(Path(__file__).resolve().parent / "outputs"),
                   help="Directory to write timestamped results and latest.json (default: benchmarks/outputs)")
    p.add_argument("--reuse-cipher", action="store_true", help="Reuse a single BES instance across loops to reduce setup overhead")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    outputs_dir = Path(args.outputs_dir)

    run_benchmark(
        loops=args.loops,
        data_size=args.data_size,
        runs_per_eta=args.runs_per_eta,
        outputs_dir=outputs_dir,
        reuse_cipher=args.reuse_cipher,
    )


if __name__ == "__main__":
    main()
