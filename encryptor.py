import os
from constants import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad


class Encryptor:
    def __init__(self) -> None:
        self.iv = b'\x00' * AES.block_size
        self.key = os.urandom(AES_KEY_SIZE)

    @staticmethod
    def encrypt_pub_key(text: bytes, pubkey: bytes) -> bytes:
        """ Encrypts text using the given public RSA key """
        rsa_pubkey = RSA.importKey(pubkey)
        rsa_pubkey = PKCS1_OAEP.new(rsa_pubkey)
        return rsa_pubkey.encrypt(text)

    def decrypt_AES(self, text: bytes, aeskey: bytes):
        """ Decrypts the text using the given AES key, we assume IV is 0 """
        cipher = AES.new(aeskey, AES.MODE_CBC, self.iv)
        raw = cipher.decrypt(text)
        return unpad(raw, AES.block_size)
