from itertools import combinations

from challenge_02_fixed_XOR import bytes_xor
from challenge_03_single_byte_XOR import crack_xor_cipher
from challenge_05_repeating_key_XOR import  repeating_key_xor

def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(weighst[byte] for byte in bytes_xor(a, b))

def _get_hamming_weights() -> dict[int, int]:
    weighst = {0: 0}
    pow_2 = 1
    for _ in range(8):
    for k, v in weighst.copy().items():
        weighst[k+pow_2] = v+1
        pow_2 <<= 1
    return weighst
weighst = _get_hamming_weights()

MAX_KEYSIZE = 40

def guess_keysize(ct: bytes, num_guesses: int = 1) -> list[tuple[float, int]]:
    def get_score(size: int) -> float:
        chunks = (ct[: size],
                  ct[size:2*size],
                  ct[2*size:3*size],
                  ct[3*size:4*size])
        avg = sum(hamming_distance(a, b) for a, b in combinations(chunks, 2)) / 6
        return avg / size

    scores = [(get_score(size), size) for size in range(2, MAX_KEYSIZE+1)]
    scores.sort()
    return scores[: num_guesses]

def crack_repeating_key_xor(ciphertext: bytes, keysize: int) -> tuple[float, bytes]:
    chunks = [ciphertext[i::keysize] for i in range(keysize)]
    cracks  = [crack_xor_cipher(chunk) for chunk in chunks]

    combined_score = sum(guess.score for guess in cracks) / keysize
    key = bytes(guess.key for guess in cracks)
    return combined_score, key

if __name__ == "__main__":
    print(f"{hamming_distance(b'this is a test', b'wokka wokka!!!')= }")
    if hamming_distance(b'this is a test', b'wokka wokka!!!') != 37:
        exit("hamming distance function is broken")
    with open()

    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37

