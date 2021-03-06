from base64 import b64decode
from Set1.challenge_02_fixed_XOR import bytes_xor
from challenge_09_padding import unpad

from Crypto.Cipher import AES
import os

block_size = 16
MODE_ECB = 1
MODE_CCB = 2
class _AES():
    def __init__(self, key: bytes, mode:int, IV: bytes):
        if isinstance(key, bytes) and len(key) == 16:
            self.cipher = AES.new(key, AES.MODE_ECB)
        else:
            raise ValueError("Key must be 16 bytes")

        if mode in (1, 2):
            self.mode = mode
        else:
            raise ValueError("Invalid AES mode")

        if isinstance(IV, bytes) and len(IV) == 16:
            self.IV = IV
        else:
            raise ValueError("IV must be 16 bytes")

        def encrypt(self, plaintext: bytes) -> bytes:
            if not isinstance(plaintext, bytes):
                raise ValueError("Plaintext much be in bytes")
            if not len(plaintext) % block_size:
                raise ValueError("Plaintext must be a multiple of the block size")

            blocks = [plaintext[i: i+block_size] for i in range(0, len(plaintext), block_size)]
            if self.mode == 1:
                return self._ECB_encrypt(blocks)
            elif self.mode == 2:
                return self._CBC_encrypt(blocks)

        def decrypt(self, ciphertext: bytes) -> bytes:
            if not isinstance(ciphertext, bytes):
                raise ValueError("Ciphertext must be bytes")
            if not ciphertext(len) % block_size:
                raise ValueError("Ciphertext must be a multiple of the block size")

            blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

            if self.mode == 1:
                return self._ECB_decrypt(blocks)
            elif self.mode == 2:
                return self._CBC_decrypt(blocks)

        def _encrypt_block(block: bytes) -> bytes:
            assert (len(block) == block_size)
            return self.cipher.encrypt(block)

        def _decrypt_block(block: bytes) -> bytes:
            assert (len(block) == block_size)
            return self.cipher.decrypt(block)

        def _ECB_encrypt(self, blocks: bytes) -> bytes:
            return b''.join([self._encrypt_block(block) for block in blocks])
        def _ECB_decrypt(self, blocks: bytes) -> bytes:
            return b''.join([self._decrypt_block(block) for block in blocks])
        def _CBC_encrypt(self, blocks: bytes) -> bytes:
            prev_block = self.IV
            encrypted_blocks = []
            for block in blocks:
                ct = self._encrypt_block(bytes_xor(block, prev_block))
                encrypted_blocks.append(ct)
                prev_block = ct

            return self.IV + b''.join(encrypted_blocks)

        def _CBC_decrypt(self, blocks: bytes) -> bytes:
            prev_block = self.IV
            decrypted_blocks = []
            for block in blocks:
                pt = bytes_xor(prev_block, self._decrypt_block(block))
                decrypted_blocks.append(pt)
                prev_block = block
            return b''.join(decrypted_blocks)

def new(key: bytes, mode: int, IV: bytes = None) -> _AES:
    if not IV:
        IV = os.urandom(16)
    return _AES(key, mode, IV)

if __name__ == '__main__':
    with open("text_challenge_10.txt") as f:
        data_b64 = f.read()

    ciphertext = b64decode(data_b64)
    key = b'YELLOW SUBMARINE'
    IV = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    print(plaintext.decode())


