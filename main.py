import bes

def main() -> None:
    algo = bes.BES(b"16ByteKey16Bytes")
    data = b"Hello, World! This is a test message for the BES encryption algorithm"
    enc_data, nonce, tag = algo.encrypt(data=data)
    print(f"Encrypted data: {enc_data.hex()}")
    dec_data = algo.decrypt(data=enc_data, nonce=nonce, tag=tag)
    print(f"Decrypted data: {dec_data.decode('utf-8')}")

if __name__ == '__main__':
    main()