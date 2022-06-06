from Set2.challenge_09_padding import pad
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

    blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]

    return 'ECB' if len(blocks) != len(set(blocks)) else 'CBC'

if __name__ == '__main__':
    oracle = encryption_oracle()
    detections = []

    for _ in range(10):
        detections.append(ECB_CBC_detect(oracle))

    print(f"Correct: {detections == oracle.arr} \nactual: {oracle.arr} \nexpect: {detections}")

