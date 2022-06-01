from dataclasses import dataclass, astuple
from typing import Optional
from collections import Counter
from challenge_02_fixed_XOR import bytes_xor
from string import ascii_letters

with open("someText.txt") as f:
     book = f.read()


def get_freqs(text, letters):
    counts = Counter()
    for letter in letters:
        counts[letter] += text.count(letter)
    total = sum(counts.values())
    return {letter: counts[letter] / total for letter in letters}

frequencies = get_freqs(book, ascii_letters)

@dataclass(order=True)
class ScoredGuess:
    score: float = float("inf")
    key: Optional[int] = None
    ciphertext: Optional[bytes] = None
    plaintext: Optional[bytes] = None

    @classmethod

    def from_key(cls, ct, key_val):
        full_key = bytes([key_val]) * len(ct)
        pt = bytes_xor(ct, full_key)
        score = score_text(pt)
        return cls(score, key_val, ct, pt)

def score_text(text: bytes) -> float:
    score = 0.0
    l = len(text)

    for letter, frequency_expected in frequencies.items():
        frequency_actual = text.count(ord(letter)) / l
        err = abs(frequency_expected - frequency_actual)
        score += err

    return score


def crack_xor_cipher(ct: bytes) -> ScoredGuess:
    best_guess = ScoredGuess()

    ct_len = len(ct)
    ct_freqs = {b: ct.count(b) / ct_len for b in range(256)}


    for candidate_key in range(256):
        score = 0
        for letter, frequency_expected in frequencies.items():
            score += abs(frequency_expected - ct_freqs[ord(letter) ^ candidate_key])
        guess = ScoredGuess(score, candidate_key)
        best_guess = min(best_guess, guess)

    if best_guess.key is None:
        exit("no key found")
    best_guess.ciphertext = ct
    best_guess.plaintext = bytes_xor(ct, bytes([best_guess.key]) * len(ct))

    return best_guess


if __name__ == "__main__":
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    best_guess = crack_xor_cipher(ciphertext)
    score, key, ciphertext, plaintext = astuple(best_guess)
    print(f"{ key = }")
    print(f"{ plaintext = }")