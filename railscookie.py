from Crypto.Cipher import AES
from Crypto import Random

import hashlib


class MessageEncryptor(object):
    def __init__(self, secret: bytes, sign_secret: bytes):
        self.secret = secret
        self.sign_secret = sign_secret
        self.cipher = "AES-256-CBC"
        self.digest = "SHA1"

    def encrypt_and_sign(self, value: bytes) -> bytes:
        pass

    def _encrypt(self, value: bytes) -> bytes:
        cipher = self._new_cipher(self.secret)
        return cipher.encrypt(value)


    def _new_cipher(self, key, iv=None):
        if iv is None:
            iv = Random.new().read(16)
        return AES.new(key, mode=AES.MODE_CBC, IV=iv)

class RailsCookie(object):
    def __init__(self, secret_key_base: bytes):
        secret = self._generate_key(secret_key_base, b"encrypted cookie")[:32]
        sign_secret = self._generate_key(secret_key_base, b"signed encrypted cookie")

    def _generate_key(self, secret: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha1", secret, salt, 64)

    def loads(self, cookie):
        pass
