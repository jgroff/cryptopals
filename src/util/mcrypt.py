""" Provides cryptographic functions and algorithms to assist with the
cryptopals challenges. Uses pycrypto, however only uses the ECB mode
from Cipher. Everything else is self implemented. (i.e., we don't want
to implement the mathmatical encryption algorithm of AES.) """

from Crypto.Cipher import AES as _AES

class Aes(object):
    """ An implementation of AES routines. """

    def __init__(self, key):
        """ Setup the AES Cipher. Key must be a bytes object """
        if type(key) != bytes and type(key) != bytearray:
            raise ValueError("key must be a bytes or bytearray")
        self.__cipher = _AES.AESCipher(key, _AES.MODE_ECB)

    def ecbEncrypt(self, data):
        """ Encrypts the given data in ECB mode """
        return self.__cipher.encrypt(data)

    def ecbDecrypt(self, data):
        """ Decrypts the given data in ECB mode """
        return self.__cipher.decrypt(data)
