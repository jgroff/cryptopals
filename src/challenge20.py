from base64 import b64decode
from util.mcrypt import *
from util.asciifunc import calculateBestXoredWeight

def importAndEncryptLines():
    """ Imports and encrypts lines from data20.txt """
    # Read them all in and decode them from base64.
    f = open("../data/data20.txt", 'r')
    lines = []
    for line in f:
        lines.append(b64decode(line))
    # Generate random key and encrypt the lines
    aes = Aes(generateRandomBytes(16))
    encLines = []
    for line in lines:
        encLines.append(aes.ctrEncrypt(line, 0))
    return encLines

def solveChallenge20():
    """ Solves Cryptopals Challenge 20 """
    # Call the function to setup the exercise.
    encLines = importAndEncryptLines()
    # Transpose the list.
    maxLen = len(max(encLines, key=len))
    minLen = len(min(encLines, key=len))
    bytesInColumns = [bytearray() for _ in range(maxLen)]
    for line in encLines:
        i = 0
        for b in line:
            bytesInColumns[i].append(b)
            i = i + 1
    # Shortcut for lazy typing.
    bic = bytesInColumns
    keystream = bytearray()
    for i in range(maxLen):
        block = bic[i]
        b, s = calculateBestXoredWeight(block)
        keystream.extend(b)
    ks = keystream
    enl = encLines
    # Keystream should be figured out at this point. Print decoded lines
    # So this gets us to a really good start. We have to work out the rest
    # the same way manually we did in challenge 19.
    ks[0] = ks[0] ^ ord('M') ^ ord('J')
    #ks.append(enl[1][21] ^ ord(' '))
    # I'm calling this good enough.
    
    for line in encLines:
        print(xor(keystream, line)[:len(line)])
    
if __name__ == "__main__":
    solveChallenge20()


