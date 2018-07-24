#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import traceback
import json
import base64

"""
使用aes ecb 模式对字符串进行加密
"""

class Prpcrypt():
    """ 使用key 对数据进行加密
    """
    def __init__(self, key):
        self.key = key
        # 密码分组链接模式
        self.mode = AES.MODE_ECB
        self.BS = AES.block_size

    def pad(self, s):
        """ 填充标准 当字符串长度不足 16的倍数时 使用此方式补齐
        """
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)

    def unpad(self, s):
        return s[0:-ord(s[-1])]

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode)
        text = self.pad(text)
        self.ciphertext = cryptor.encrypt(text)
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return self.unpad(plain_text)

aes = Prpcrypt("1er3yuikjhgfdsa")
