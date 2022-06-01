from challenge_03_single_byte_XOR import crack_xor_cipher, ScoredGuess

if __name__ == "__name__":
    with open("text_challenge_4.txt") as f:
        lines = [bytes.fromhex(line.strip()) for line in f]

    overall_best = ScoredGuess()
    for line in lines:
        candidate = crack_xor_cipher(line)
        overall_best = min(overall_best, candidate)


    print(overall_best)