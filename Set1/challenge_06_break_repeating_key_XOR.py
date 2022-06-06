from itertools import combinations
from base64 import b64decode
from pprint import pprint

from Set1.challenge_02_fixed_XOR import bytes_xor
from Set1.challenge_03_single_byte_XOR import crack_xor_cipher
from Set1.challenge_05_repeating_key_XOR import repeating_key_xor

def hamming_distance(a: bytes, b: bytes) -> int:
    print(weights)
    return sum(weights[byte] for byte in bytes_xor(a, b))

def _get_hamming_weights() -> dict[int, int]:
    weights = {0: 0}
    pow_2 = 1
    for _ in range(8):
        for k, v in weights.copy().items():
            weights[k+pow_2] = v+1
            pow_2 <<= 1
    return weights
weights = _get_hamming_weights()

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
    cracks = [crack_xor_cipher(chunk) for chunk in chunks]

    combined_score = sum(guess.score for guess in cracks) / keysize
    key = bytes(guess.key for guess in cracks)
    return combined_score, key

if __name__ == "__main__":
    # print(f"{hamming_distance(b'this is a test', b'wokka wokka!!!')}")
    hamming_distance(b'this is a test', b'wokka wokka!!!')
    if hamming_distance(b'this is a test', b'wokka wokka!!!') != 37:
        exit("hamming distance function is broken")
    with open("text_challenge_6.txt") as f:
        b64 = f.read()
    ciphertext = b64decode(b64)

    keyssizes = guess_keysize(ciphertext, 5)
    print("Best key size guesses (confidence, size): ")
    pprint(keyssizes)

    candidates = [crack_repeating_key_xor(ciphertext, guess) for _, guess in keyssizes]
    candidates.sort()
    best_candidate = candidates[0]
    best_key = candidates[1]

    print("Top guess: ")
    print(f"{best_key = }")
    print("plaintext = \n")
    print(repeating_key_xor(best_key, ciphertext).decode("ascii"))

