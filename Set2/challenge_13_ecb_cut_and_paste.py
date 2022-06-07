from challenge_09_padding import pad, unpad
from challenge_10_cbc_mode import AES
from os import urandom

class profile_service:
    def __init__(self):
        self.cipher = AES.new(urandom(16), AES.MODE_ECB)
        self.next_uid = 10

    def encrypt_profile_for(self, address: str) -> bytes:
        profile = self._profile_for(address)
        return self.cipher.encrypt(pad(profile.encode(), AES.block_size))

    def decrypt_profile(self, profile: bytes) -> dict:
        params = unpad(self.cipher.decrypt(profile), AES.block_size).decode()
        return self._param_parse(params)

    def _param_parse(self, params: bytes) -> dict:
        return dict(param.split('=') for param in params.split('&'))

    def _profile_for(self, address: str) -> str:
        if '&' in address or '=' in address:
            raise ValueError("Address can't have '&' and '='")

        profile = f"email={address}&uid={self.next_uid}&role=user"
        self.next_uid += 1

        return profile

if __name__ == '__main__':
    oracle = profile_service()

    serv = oracle.encrypt_profile_for("foo@bar.com")
    print(oracle.decrypt_profile(serv))

    garbage = b'AAAAAAAAAAadmin' + b'\x0b'*11 +b'@barr.com'
    garbage_account = oracle.encrypt_profile_for(garbage.decode())
    print(oracle.decrypt_profile(garbage_account))

    log = serv[:32] + garbage_account[16:32]
    print(oracle.decrypt_profile(log))





