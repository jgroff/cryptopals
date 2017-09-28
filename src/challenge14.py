import base64
from util.mcrypt import *

import binascii

class Challenge14Encryptor(object):
    """ An encryptor object for helping with challenge 12 """

    def __init__(self):
        """ Initialize the encryptor. """
        self.__aes = Aes(generateRandomAesKey())
        f = open("../data/data12.txt", 'r')
        self.__appendBytes = base64.b64decode(f.read())
        f.close()

    def encrypt(self, data):
        """ Encrypts data according to challenge 14 description """
        # For the purpose of this exercise, setting the number of random
        # bytes generated to be between 0 and 16, inclusive, is sufficient.
        prependBytes = generateRandomBytes(random.randint(0, 16))
        data = prependBytes + data + self.__appendBytes
        data = padPkcs7(data, 16)
        return self.__aes.ecbEncrypt(data)
    
    def decrypt(self, data):
        return self.__aes.ecbDecrypt(data)

def decryptEcbConstantAppendRandomPrepend(encFunc, decFunc, blockSize):
    """ Decryptor for the encryption function in this file. """
    f = open("test.log", 'w')
    # The difference between this challenge and challenge 12 is that
    # the beginning of the encrypted data is uncontrolled by us - there
    # are a random number of random bytes at the beginning of the encrypted
    # bytes. Therefore we need to make a placefinder.
    # First, create the placefinder bytes.
    pfBytes = "Z".encode() * blockSize
    # Now, put three blocks of these bytes to be encrypted - this will create
    # at minimum two blocks that are identical when encrypted, which should
    # be what the ecb blocksize encryption of the pfBytes is.
    # Find the identical blocks and figure out what they are.
    tempEnc = encFunc(pfBytes*3)
    pfEncrypted = isEcbEncrypted(tempEnc, False)
    # We can now identify a block of our placefinder bytes in ecb encrypted
    # data.
    # We prepend all of our test data with these pfBytes and use this to line
    # up our data. We look for a block that is <pfEncrypted> then we do the
    # same thing to the data AFTER that block that we were doing in challenge
    # 12. Lets make an intermediate encryption function that will encrypt
    # over and over until it finds the block, then chops the block and
    # everything before it, to give us the same data as encFunc
    def encWithPf(data):
        data = pfBytes + data
        #f.write(data.decode())
        #f.write('\n')
        while True:
            encBytes = encFunc(data)
            if pfEncrypted in encBytes:
                break
        # rfind because there's the possibility that 
        i = encBytes.rfind(pfEncrypted) + blockSize
        #f.write(binascii.hexlify(encBytes).decode())
        #f.write('\n')
        #f.write(binascii.hexlify(decFunc(encBytes)).decode())
        #f.write('\n')
        return encBytes[i:]
    # This following code is copied from challenge 12. The changes are
    # encWithPf instead of encFunc, and the addition of the while loop.
    # The while loop is because the random bytes created by encrypt may
    # cause ghosting against the repeated bytes used to generate the
    # placefinder (e.g., if one random byte "Z" is generated, it will produce
    # the same block when prepended to the placefinder bytes, but it then
    # causes an extra Z at the beginning of the next.) So if a full loop around
    # does not produce the correct answer, try again.
    # Note - THERE ARE STILL ISSUES WITH THIS IMPLEMENTATION.
    # It's possible that the problem meant "choose a random length and bytes
    # but then use the same random length and bytes" (just like the key)
    # which would make this a whoooooole lot easier. But hey, I'm doing this
    # the hard way perhaps.

    # Also added is the calculation for how long the encrypted bytes we're
    # interested in is.
    # Calculate how long the encrypted text is.
    blankLen = len(encWithPf(bytes(0)))
    for n in range(1, blockSize):
        addLen = len(encWithPf(bytes(n)))
        print(blankLen, addLen)
        if addLen > blankLen:
            offset = blockSize - n
            break
    print(n, offset)
    numIters = blankLen // blockSize
    lenEncText = ((numIters - 1)* blockSize) + offset
    # Initialize
    decryptedBytes = bytearray()
    paddingBytes = bytearray('A'.encode() * blockSize)
    # Decrypt block by block
    for blockNum in range(numIters):
        for blockByte in range(blockSize - 1, -1, -1):
            while True:
                # Each time a byte is decrypted, the encryption function is
                # run with two sets of input. The first is a single input with 
                # padding bytes to shift an output byte to where we need it. The
                # second is a set of 256 inputs, representing all bytes, to
                # determine what that byte is.
                realOutput = encWithPf(bytes(paddingBytes[0 : blockByte]))
                # Make the test outputs
                testPrefix = paddingBytes[0 : blockByte] + decryptedBytes
                start = blockNum * blockSize
                end = (blockNum + 1) * blockSize
                found = False
                for b in range(256):
                    testInput = bytes(testPrefix + bytes([b]))
                    testOutput = encWithPf(testInput)
                    if realOutput[start : end] == testOutput[start : end]:
                        decryptedBytes.append(b)
                        found = True
                        print("blockNum %d  blockByte %d  Byte is 0x%02x" % \
                            (blockNum, blockByte, b))
                        break
                if found:
                    break
            if len(decryptedBytes) == lenEncText:
                break

    return bytes(decryptedBytes)

def solveChallenge14():
    """ Solves Cryptopals Challenge 14 """
    # Create the encryptor.
    enc = Challenge14Encryptor()
        
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
    decryptedBytes = \
            decryptEcbConstantAppendRandomPrepend(enc.encrypt, enc.decrypt,blockSize)
    print(decryptedBytes.decode('ascii'))
       


if __name__ == "__main__":
    solveChallenge14()
