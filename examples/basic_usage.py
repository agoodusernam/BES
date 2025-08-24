"""Basic usage example for BES.

Run: python examples/basic_usage.py

Note: BES is experimental and not for production use. See README for security disclaimer.
"""

import bes


def main() -> None:
    key = b"16ByteKey16Bytes"  # 16 bytes for n=4
    algorithm = bes.BES(key)

    plaintext = b"Hello, World!"
    # Provide a fresh nonce (or omit to let BES generate internally)
    nonce = bes.generate_nonce(size=4)
    ciphertext, used_nonce, tag = algorithm.encrypt(data=plaintext, nonce=nonce)

    print("Encrypted data (hex):", ciphertext.hex())

    recovered = algorithm.decrypt(data=ciphertext, nonce=used_nonce, tag=tag)
    print("Decrypted data:", recovered.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
