import base64
from util.mcrypt import *

class Challenge12Encryptor(object):
    """ An encryptor object for helping with challenge 12 """

    def __init__(self):
        """ Initialize the encryptor. """
        self.__aes = Aes(generateRandomAesKey())
        f = open("../data/data12.txt", 'r')
        self.__appendBytes = base64.b64decode(f.read())
        f.close()

    def encrypt(self, data):
        """ Encrypts data according to challenge 12 description """
        data = data + self.__appendBytes
        data = padPkcs7(data, 16)
        return self.__aes.ecbEncrypt(data)

def decryptEcbConstantAppend(encFunc, blockSize):
    """ Decryptor for the encryption function in this file. """
    # Calculate how many iterations are required to decrypt the text.
    temp = encFunc(bytes())
    numIters = len(temp) // blockSize
    # Initialize
    decryptedBytes = bytearray()
    paddingBytes = bytearray('A'.encode() * blockSize)
    # Decrypt block by block
    for blockNum in range(numIters):
        for blockByte in range(blockSize - 1, -1, -1):
            # Each time a byte is decrypted, the encryption function is
            # run with two sets of input. The first is a single input with 
            # padding bytes to shift an output byte to where we need it. The
            # second is a set of 256 inputs, representing all bytes, to
            # determine what that byte is.
            realOutput = encFunc(bytes(paddingBytes[0 : blockByte]))
            # Make the test outputs
            testPrefix = paddingBytes[0 : blockByte] + decryptedBytes
            start = blockNum * blockSize
            end = (blockNum + 1) * blockSize
            for b in range(256):
                testInput = bytes(testPrefix + bytes([b]))
                testOutput = encFunc(testInput)
                if realOutput[start : end] == testOutput[start : end]:
                    decryptedBytes.append(b)
                    #print("blockNum %d  blockByte %d  Byte is 0x%x" % \
                    #      (blockNum, blockByte, b))
                    break
    return bytes(decryptedBytes)

def solveChallenge12():
    """ Solves Cryptopals Challenge 12 """
    # Create the encryptor.
    enc = Challenge12Encryptor()
        
    # Determine block size of the encryptor
    blockSize = determineBlockSize(enc.encrypt)
    print("Determined Blocksize to be %d" % (blockSize,))

    # Make certain this is ECB
    testData = enc.encrypt(bytes("A".encode()*1000))
    if (isEcbEncrypted(testData)):
        print("This is ECB Encrypted")
    else:
        print("This is not ECB Encrypted!")
        raise AssertionError("Challenge expects ECB Encoding")

    # Knowing it's ECB, and the blocksize, attempt to decrypt.
    decryptedBytes = decryptEcbConstantAppend(enc.encrypt, blockSize)
    print(decryptedBytes.decode())
       


if __name__ == "__main__":
    solveChallenge12()
