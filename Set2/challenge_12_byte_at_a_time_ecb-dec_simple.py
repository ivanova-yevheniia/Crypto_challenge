from Set2.challenge_11_ecb_cbc_detection_oracle import encryption_oracle_interface, ECB_CBC_detect
from challenge_10_cbc_mode import AES
from challenge_09_padding import pad
from base64 import b64decode
from os import urandom


class encryption_oracle(encryption_oracle_interface):
    def __init__(self):
        self.key = urandom(16)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.secret = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                "YnkK")

    def encryption(self, data: bytes) -> bytes:
        plaintext = data + self.secret

        return self.cipher.encrypt(pad(plaintext, AES.block_size))

def get_block_size(oracle: type[encryption_oracle_interface]) -> int:
    test = b''
    base_len = len(oracle.encryption(test))
    new_len = base_len

    while new_len == base_len:
        test += b'A'
        new_len = len(oracle.encryption(test))

    return new_len - base_len

def recover_secret(oracle: type[encryption_oracle_interface], secret_size: int) -> bytes:
    assert(ECB_CBC_detect(oracle) == 'ECB')

    feed = b'A' * secret_size
    recovered = b''
    for i in range(secret_size):
        plaintext = feed[:-i]
        ciphertext = oracle.encryption(plaintext)
        to_match = ciphertext[:secret_size]
        for b in range(256):
            test = plaintext + recovered + bytes([b])
            if oracle.encryption(test)[:secret_size] == to_match:
                recovered += bytes([b])
                break

    return recovered

if __name__ == '__main__':
    oracle = encryption_oracle()
    secret_size = len(oracle.encryption(b''))
    secret = recover_secret(oracle, secret_size)

    print(secret.decode())
