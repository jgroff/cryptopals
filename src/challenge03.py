from util.asciifunc import calculateBestXoredWeight
from util.bmanip import xor

_inputHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def solveChallenge03():
    """ Solves Cryptopals Challenge 03 """
    inputBytes = bytes.fromhex(_inputHex)
    (highByte, highScore) = calculateBestXoredWeight(inputBytes)
    print("Byte 0x%x had the highest score of %.2f" % (highByte[0], highScore))
    decString = xor(inputBytes, highByte)
    print("Decoded String: %s" % (decString.decode()))

if __name__ == "__main__":
    solveChallenge03()
