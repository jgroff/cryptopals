from math import floor
import random

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
        self.__cipher = _AES.new(key, _AES.MODE_ECB)

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
        # Handle padding on the last block.
        lastBlock = padPkcs7(data[numBlocks * 16 :], 16)
        encBlock = self.ecbEncrypt(xor(lastBlock, prevBlock))
        encData.extend(encBlock)
        return bytes(encData)

    def cbcDecrypt(self, data, iv):
        """ Decrypts the given data in CBC mode """
        if len(iv) != 16:
            raise ValueError("IV must be of length 16")
        decData = bytearray()
        numBlocks = floor(len(data) / 16)
        prevBlock = iv
        for i in range(0, numBlocks):
            blockToDecode = data[i * 16 : (i * 16) + 16]
            decBlock = xor(self.ecbDecrypt(blockToDecode), prevBlock)
            prevBlock = blockToDecode
            decData.extend(decBlock)
        # There shouldn't be bytes leftover if handled properly.
        if len(data) % 16 != 0:
            raise ValueError("Implement handling non-16-byte-multiple blocks")
        return bytes(decData)

def isEcbEncrypted(b, returnBool=True):
    """ Given a bytes object, does a simple check to see if this might be
        ECB encrypted. If any two 16 byte segments contain the same data,
        returns True. else, returns False. """
    
    for i in range(0, len(b), 16):
        for j in range(i + 16, len(b), 16):
            chunk1 = b[i : i + 16]
            chunk2 = b[j : j + 16]
            if chunk1 == chunk2:
                if (returnBool):
                    return True
                else:
                    return chunk1
    if (returnBool):
        return False
    else:
        return bytes()

def padPkcs7(dataBytes, blockSize):
    """ Pads the given dataBytes using PKCS#7 padding. Pads to the given
    blocksize. """
    modVal = len(dataBytes) % blockSize
    padVal = blockSize - modVal
    padBytes = bytes([padVal] * padVal)
    return dataBytes + padBytes

def unpadPkcs7(dataBytes, blockSize):
    """ Unpads pkcs7 padding. """
    # Last byte is ALWAYS the size of the padding.
    padSize = dataBytes[-1]
    if padSize == 0:
        raise ValueError("data is padded improperly.")
    for i in range(1, padSize + 1):
        if dataBytes[-i] != padSize:
            raise ValueError("data is padded improperly.")
    return dataBytes[:len(dataBytes) - padSize]

def generateRandomAesKey():
    """ Generates a random AES key """
    return generateRandomBytes(16)

def generateRandomBytes(num):
    """ Generates a number of random bytes as requested by the argument """
    b = bytes(random.getrandbits(8) for i in range(num))
    return b

def determineEcbBlockSize(encFunc):
    """ Determines ECB Block Size of an encryption function that
    takes raw bytes in and returns encrypted bytes. The function
    should have only one argument, the data (the key is handled
    by the function or elsewhere)
    """
    # No assumption is made to if padding is added or not, therefore
    # we will base this off of repeated blocks (it IS ECB after all)
    # We are testing for blocksizes in the range in the loop.
    for blockSize in range(2, 128 + 1):
        # Create test bytes double the length we are testing for.
        testBytes = bytes('A'.encode() * (blockSize * 2))
        # Encode
        encBytes = encFunc(testBytes)
        # If this is the block size, then we'll have two identical blocks
        # of size blockSize next to each other
        if encBytes[0 : blockSize] == encBytes[blockSize : blockSize * 2]:
            return blockSize
    # If we get to the end, throw an exception
    raise ValueError("Could not determine ECB blocksize")

def determineBlockSize(encFunc):
    """ Determines block size of an encoding function. Assumes that
    padding causes the function to be multiples of the blocksize at
    all times.
    """
    curEncSize = len(encFunc("A".encode()))
    for n in range (2, 256):
        newEncSize = len(encFunc("A".encode() * n))
        if newEncSize != curEncSize:
            return abs(newEncSize - curEncSize)
    return 0

