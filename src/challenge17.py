from random import randint
from base64 import b64decode
from util.mcrypt import *

_STRING1 = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
_STRING2 = "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
_STRING3 = "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
_STRING4 = "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
_STRING5 = "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
_STRING6 = "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
_STRING7 = "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
_STRING8 = "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
_STRING9 = "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
_STRING10 = "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
_BYTESTRINGS = [b64decode(_STRING1),
                b64decode(_STRING2),
                b64decode(_STRING3),
                b64decode(_STRING4),
                b64decode(_STRING5),
                b64decode(_STRING6),
                b64decode(_STRING7),
                b64decode(_STRING8),
                b64decode(_STRING9),
                b64decode(_STRING10)]

class Challenge17Helper(object):
    """ A helper object for challenge 17. Implements the functions
    as specified in the challenge. """
    
    def __init__(self):
        """ Intializes the object. """
        self.__aes = Aes(generateRandomAesKey())
    
    def encrypt(self):
        """ Encrypts data according to challenge 17 guidelines. """
        # generate an IV
        iv = generateRandomBytes(16)        
        # Pick one of the strings at random to encrypt.
        i = randint(0, 9)
        ciphertext = self.__aes.cbcEncrypt(_BYTESTRINGS[i], iv)
        return (ciphertext, iv)
    
    def decryptCheckPadding(self, data, iv):
        """ Decrypts data, checks the padding, and returns True if the padding
        is valid and False if the padding is not valid. """
        dec = self.__aes.cbcDecrypt(data, iv)
        good = True
        try:
            dec = unpadPkcs7(dec, 16)
        except ValueError:
            good = False
        return good

def decryptBlock(checkFunc, curBlock, prevBlock):
    """ Helper function for the padding oracle attack. Decrypts a single
    block and returns the decrypted text.
    """
    blockSize = len(curBlock)
    pos = blockSize - 1
    targetPad = 1
    decryptedBytes = bytearray(blockSize)
    # The checkFunc returns "padding is good" or "padding is bad" in the form
    # of a True or False, respectively. This will help us decrypt a block.
    # Strategy: Manipulate the bits in prevBlock until when fed to the check
    # function (prevBlock is iv, curBlock is data) we get a True return for
    # paddingGood. Knowing what bytes we manipulated and knowing the padding,
    # we can back out what the plaintext is.
    # Initially we do not know the padding.
    # First, we need to check the special case of there being actual padding
    # bytes (or at least bytes that look like padding)
    # Check the prevBlock and curBlock unaltered.
    if checkFunc(curBlock, prevBlock):
        #print("Initial Special Case")
        # Padding was reported as good. Figure out what the current padding is.
        # Start at the beginning, flip a single bit per byte until the return
        # fails, what's leftover is padding, and we can add that to decrypted
        # and decrease blockPos
        testBlock = bytearray(prevBlock)
        for i in range(blockSize):
            testBlock[i] ^= 0x01
            if (not checkFunc(curBlock, testBlock)):
                # Ok, this is the byte.
                for n in range(i, blockSize):
                    decryptedBytes[n] = blockSize - i
                pos = i - 1
                targetPad = blockSize - pos
                break
        # Special case, if pos is -1, (i was 0) then this is a full block of
        # padding.
        if pos == -1:
            return bytes([blockSize] * blockSize)
    # For all the bytes in reverse order:
    # xor the bytes in prevBlock with the bytes in decryptedBytes. This will
    # give 0x00 in the plaintext upon decryption in the byte positions for
    # the bytes we know.
    # Then for the byte that we're on, counting in the reverse order, flip
    # the bits again to set the known bytes to the target pad, e.g., if we're
    # on the third byte from the end, the target pad is 0x03 (and we'll know
    # two bytes so far).
    # Then for the byte we're examining, try all possible bitflips of that byte
    # and feed it to the function. When we get a True return, we know the
    # bitflip that gets us that pad number. Back out the plaintext byte from
    # that information.
    # How to back it out:
    # 1. prevByte ^ decryptByte = plainByte
    # 2. tamperedByte ^ decryptByte = padByte ->
    #       decryptByte = padByte ^ tamperedByte ->
    #       prevByte ^ padByte ^ tamperedByte = plainByte   
    while True:
        # Create the 0x00s in known positions
        testBlock = bytearray(a ^ b for a, b in zip(prevBlock, decryptedBytes))
        # Change them to the target pad
        for i in range(pos + 1, blockSize):
            testBlock[i] ^= targetPad
        # Now check the target position.
        for i in range(256):
            testBlock[pos] = i
            if (checkFunc(curBlock, testBlock)):
                # Found it.
                decryptedBytes[pos] = i ^ targetPad ^ prevBlock[pos]
                break
        pos = pos - 1
        targetPad = targetPad + 1
        if pos == -1:
            break
    # This...should do it.
    return bytes(decryptedBytes)

def performCbcPaddingOracleAttack(checkFunc, ciphertext, iv):
    """ Decrypts a CBC encoded ciphertext given the ciphertext,
    the IV, and a function that when called with ciphertext and an IV is
    able to check to see if that ciphertext is padded properly, and returns
    True if it is and False if not padded properly.
    """
    # May as well assume blockSize of 16, no need to calculate it.
    blockSize = 16
    # How many blocks will be decrypted
    numBlocks = len(ciphertext) // 16
    # Decrypt it all.
    decryptedBytes = bytearray()
    prevBlock = iv
    for b in range(numBlocks):
        block = ciphertext[b * blockSize : (b + 1) * blockSize]
        decryptedBytes.extend(decryptBlock(checkFunc, block, prevBlock))
        prevBlock = block
    return bytes(decryptedBytes)

def solveChallenge17():
    """ Solves Cryptopals Challenge 17 """
    h = Challenge17Helper()
    #encodedBytes, iv = h.encrypt()
    #if (h.decryptCheckPadding(encodedBytes, iv)):
    #    print("Check on non-tampered padding is good")
    #else:
    #    print("Check on non-standard padding FAILED")
    #    exit(1)
    # Try to solve one!
    encodedBytes, iv = h.encrypt()
    decodedBytes = performCbcPaddingOracleAttack(h.decryptCheckPadding,
                                                 encodedBytes, iv)
    print(decodedBytes)

if __name__ == "__main__":
    solveChallenge17()
