#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 CloudRunner.IO
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from os import urandom
import M2Crypto as m
from base64 import (b64encode, b64decode)

ENCODE = 1
DECODE = 0


class Crypter(object):

    def __init__(self, key=None, iv=None):
        if not key:
            self._aes_key = urandom(32)
        else:
            self._aes_key = b64decode(key)

        if not iv:
            self._aes_iv = urandom(16)
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
