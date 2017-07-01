from Crypto.Cipher import AES
from Crypto import Random

import base64
import hashlib
import hmac
from typing import Optional


class MessageVerifier(object):
    def __init__(self, secret: bytes):
        self.secret = secret

    def generate(self, value: bytes) -> bytes:
        data = self._encode(value)
        digest = hmac.new(self.secret, msg=data, digestmod="sha1").hexdigest()
        return b"--".join([data, self._encode(digest)])

    def _encode(self, data: bytes) -> bytes:
        return base64.b64encode(data)

class MessageEncryptor(object):
    def __init__(self, secret: bytes, sign_secret: bytes):
        self.secret = secret
        self.sign_secret = sign_secret
        self.verifier = MessageVerifier(secret)

    def encrypt_and_sign(self, value: bytes) -> bytes:
        return self.verifier.generate(self._encrypt(value))

    def _encrypt(self, value: bytes) -> bytes:
        cipher = self._new_cipher(self.secret)
        return b"--".join(map(base64.b64encode, [cipher.encrypt(value), cipher.IV]))

    def _new_cipher(self, key: bytes, iv: Optional[bytes]=None):
        if iv is None:
            iv = Random.new().read(16)
        return AES.new(key, mode=AES.MODE_CBC, IV=iv)

class RailsCookie(object):
    def __init__(self, secret_key_base: bytes):
        secret = self._generate_key(secret_key_base, b"encrypted cookie")[:32]
        sign_secret = self._generate_key(secret_key_base, b"signed encrypted cookie")
        self.encryptor = MessageEncryptor(secret, sign_secret)

    def _generate_key(self, secret: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha1", secret, salt, 1000, dklen=64)

    def loads(self, cookie):
        pass
