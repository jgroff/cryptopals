import re

from base64 import b64decode
from util.mcrypt import *


def importAndEncryptLines():
    """ Imports and encrypts lines from data19.txt """
    # Read them all in and decode them from base64.
    f = open("../data/data19.txt", 'r')
    lines = []
    for line in f:
        lines.append(b64decode(line))
    # Generate random key and encrypt the lines
    aes = Aes(generateRandomBytes(16))
    encLines = []
    for line in lines:
        encLines.append(aes.ctrEncrypt(line, 0))
    return encLines

def printWithGuesses(encLines, xorGuesses):
    """ Xors all positions and prints. If non ascii print ? """
    for line in encLines:
        decLine = xor(line, bytes(xorGuesses))
        decLine = bytearray(decLine)
        repLine = bytearray()
        for b in decLine:
            if b < 0x20 or b > 0x7f:
                repLine.extend(b'?')
            else:
                repLine.append(b)
        print(repLine.decode()[0:len(line)])
        

def solveChallenge19():
    """ Solves Cryptopals Challenge 19 """
    # Call the function to setup the exercise.
    encLines = importAndEncryptLines()
    # Start from the knowledge that each byte position has been xored with
    # the same byte. Transpose the list.
    maxLen = 0
    for line in encLines:
        if len(line) > maxLen:
            maxLen = len(line)
    bytesInColumns = [bytearray() for _ in range(maxLen)]
    for line in encLines:
        i = 0
        for b in line:
            bytesInColumns[i].append(b)
            i = i + 1
    # So I don't have to type as much.
    bic = bytesInColumns
    # Lets do this menually since the next exercise makes this nicer apparently.
    # The next bit is alllll from guessing. Not bothering to automate it.
    xorGuesses = [0]*40
    xor2 = bic[2][6] ^ ord(' ')
    #print(xor(xor2.to_bytes(1, 'little'), bic[2]))
    xor3 = bic[3][37] ^ ord(' ')
    #print(xor(xor3.to_bytes(1, 'little'), bic[3]))
    xorGuesses[2] = xor2
    xorGuesses[3] = xor3
    xor1 = bic[1][3] ^ ord('i')
    #print(xor(xor1.to_bytes(1, 'little'), bic[1]))
    xorGuesses[1] = xor1
    xor0 = bic[0][8] ^ ord('A')
    #print(xor(xor0.to_bytes(1, 'little'), bic[0]))
    xorGuesses[0] = xor0
    xor4 = bic[4][20] ^ ord(' ')
    xorGuesses[4] = xor4
    #print()
    xorGuesses[5] = bic[5][1] ^ ord('g')
    xorGuesses[6] = bic[6][0] ^ ord(' ')
    xorGuesses[7] = bic[7][38] ^ ord('r')
    xorGuesses[8] = bic[8][38] ^ ord('m')
    xorGuesses[9] = bic[9][39] ^ ord('e')
    xorGuesses[10] = bic[10][1] ^ ord('h')
    xorGuesses[11] = bic[11][1] ^ ord(' ')
    xorGuesses[12] = bic[12][37] ^ ord(' ')
    xorGuesses[13] = bic[13][36] ^ ord(' ')
    xorGuesses[14] = bic[14][39] ^ ord('u')
    xorGuesses[15] = bic[15][39] ^ ord('t')
    xorGuesses[16] = bic[16][39] ^ ord('y')
    xorGuesses[17] = bic[17][39] ^ ord(' ')
    xorGuesses[18] = bic[18][3] ^ ord(' ')
    xorGuesses[19] = bic[19][5] ^ ord('s')
    xorGuesses[20] = bic[20][5] ^ ord('s')
    xorGuesses[21] = bic[21][5] ^ ord(' ')
    xorGuesses[22] = bic[22][6] ^ ord('e')
    enl = encLines
    xorGuesses[23] = enl[0][23] ^ ord('e')
    xorGuesses[24] = enl[24][24] ^ ord('e')
    xorGuesses[25] = enl[19][25] ^ ord('l')
    xorGuesses[26] = enl[19][26] ^ ord('l')
    xorGuesses[27] = enl[32][27] ^ ord('n')
    xorGuesses[28] = enl[32][28] ^ ord('g')
    xorGuesses[29] = enl[0][29] ^ ord('a')
    xorGuesses[30] = enl[0][30] ^ ord('y')
    xorGuesses[31] = enl[4][31] ^ ord(' ')
    xorGuesses[32] = enl[4][32] ^ ord('h')
    xorGuesses[33] = enl[4][33] ^ ord('e')
    xorGuesses[34] = enl[4][34] ^ ord('a')
    xorGuesses[35] = enl[4][35] ^ ord('d')
    xorGuesses[36] = enl[37][36] ^ ord('n')
    xorGuesses[37] = enl[37][37] ^ ord(',')
    
    
    printWithGuesses(encLines, xorGuesses)

    #for ba in bic:
    #    print(ba)


if __name__ == "__main__":
    solveChallenge19()
