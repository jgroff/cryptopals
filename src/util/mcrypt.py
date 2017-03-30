from math import floor

from util.bmanip import xor

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

    def cbcEncrypt(self, data, iv):
        """ Encrypts the given data in CBC mode """
        if len(iv) != 16:
            raise ValueError("IV must be of length 16")
        encData = bytearray()
        prevBlock = iv
        numBlocks = floor(len(data) / 16)
        for i in range(0, numBlocks):
            blockToEncode = data[i * 16 : (i * 16) + 16]
            encBlock = self.ecbEncrypt(xor(blockToEncode, prevBlock))
            prevBlock = encBlock
            encData.extend(encBlock)
        # If there's bytes left over, handle them.
        if len(data) % 16 == 0:
            return encData
        lastBlock = padPkcs7(data[numBlocks * 16 :], 16)
        encBlock = self.ecbEncrypt(xor(lastBlock, prevBlock))
        encData.extend(encBlock)
        return encData


    def cbcDecrypt(self, data, iv):
        """ Decrypts the given data in CBC mode """


def isEcbEncrypted(b):
    """ Given a bytes object, does a simple check to see if this might be
        ECB encrypted. If any two 16 byte segments contain the same data,
        returns True. else, returns False. """
    
    for i in range(0, len(b), 16):
        for j in range(i + 16, len(b), 16):
            chunk1 = b[i : i + 16]
            chunk2 = b[j : j + 16]
            if chunk1 == chunk2:
                return True
    return False

def padPkcs7(dataBytes, blockSize):
    """ Pads the given dataBytes using PKCS#7 padding. Pads to the given
    blocksize. """
    modVal = len(dataBytes) % blockSize
    if modVal == 0:
        return dataBytes
    padVal = blockSize - modVal
    padBytes = bytes([padVal] * padVal)
    return dataBytes + padBytes
