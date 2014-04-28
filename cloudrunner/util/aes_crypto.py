import random
import M2Crypto as m
from base64 import (b64encode, b64decode)

ENCODE = 1
DECODE = 0


class Crypter(object):

    def __init__(self, key=None, iv=None):
        if not key:
            self._aes_key = ''.join(chr(random.randint(0, 0xFF))
                                    for i in range(32))
        else:
            self._aes_key = b64decode(key)

        if not iv:
            self._aes_iv = ''.join(chr(random.randint(0, 0xFF))
                                   for i in range(16))
        else:
            self._aes_iv = b64decode(iv)

    def __repr__(self):
        return "AES Crypter KEY:[%r] IV:[%r]" % (self._aes_key, self._aes_iv)

    def _create_cipher(self, enc):
        return m.EVP.Cipher('aes_256_cfb', self._aes_key, self._aes_iv, op=enc)

    @property
    def key(self):
        return b64encode(self._aes_key)

    @property
    def iv(self):
        return b64encode(self._aes_iv)

    def encrypt(self, message):
        c = self._create_cipher(ENCODE)
        enc = c.update(message)
        enc += c.final()
        del c
        return enc

    def decrypt(self, message):
        c = self._create_cipher(DECODE)
        enc = c.update(message)
        enc += c.final()
        del c
        return enc
