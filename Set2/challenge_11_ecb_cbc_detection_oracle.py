from Set2.challenge_09_padding import pad
from Set1.challenge_08_detect_AES_in_ECB_mode import bytes_to_chunks
from challenge_10_cbc_mode import AES
from random import randint
from os import urandom

class encryption_oracle_interface:
    def encryption(self, data: bytes) -> bytes:
        pass

class encryption_oracle(encryption_oracle_interface):
    def __init__(self):
        self.arr = []
        self.key = urandom(16)

    def encryption(self, data: bytes) -> bytes:
        plaintext = urandom(randint(5, 10)) + data + urandom(randint(5, 10))

        if randint(0, 1):
            self.arr.append('CBC')
            cipher = AES.new(self.key, AES.MODE_CBC)
        else:
            self.arr.append('ECB')
            cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, AES.block_size))


def ECB_CBC_detect(oracle: type[encryption_oracle_interface]) -> str:
    data = b'A' * 48
    ciphertext = oracle.encryption(data)

    return 'ECB' if contains_repeated_blocks(ciphertext) else 'CBC'

def contains_repeated_blocks(ciphertexts: bytes) -> bool:
    for i, ciphertext in enumerate(ciphertexts):
        num_blocks = len(ciphertext) // 16
        num_uniq_blocks = len(set(bytes_to_chunks(ciphertext, 16)))
        repeated_blocks = num_blocks - num_uniq_blocks
        return repeated_blocks != 0

if __name__ == '__main__':
    oracle = encryption_oracle()
    detections = []

    for _ in range(10):
        detections.append(ECB_CBC_detect(encryption_oracle))

    print(f"Correct: {detections == oracle.arr}")

