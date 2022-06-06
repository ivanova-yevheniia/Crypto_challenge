def pad(plaintext: bytes, block_size: int) -> bytes:
    padding = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding]) * padding

def unpad(padded: bytes, block_size: int) -> bytes:
    if len(padded) % block_size:
        raise ValueError("Input data isn't padded")
    if not _is_valid_padding(padded):
        raise ValueError("Not valid padding")

    return padded[:-padded[-1]]

def _is_valid_padding(padded: bytes) -> bool:
    pad = padded[-1]

    return padded[-pad:] == bytes([pad]) * pad

if __name__ == '__main__':
    example = b"YELLOW SUBMARINE"
    ans = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    result = pad(example, 20)
    print(f"Correct: {ans == result}, result: {result}")

    result = unpad(result, 20)
    print(f"Correct: {result == example}, result: {result}")