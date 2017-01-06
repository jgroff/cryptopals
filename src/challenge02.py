from util.bmanip import xor

_inputString1 = "1c0111001f010100061a024b53535009181c"
_inputString2 = "686974207468652062756c6c277320657965"
_testOutput = "746865206b696420646f6e277420706c6179"

def solveChallenge02():
    """ Solves Cryptopals Challenge 02 """
    in1Bytes = bytes.fromhex(_inputString1)
    in2Bytes = bytes.fromhex(_inputString2)
    outBytes = xor(in1Bytes, in2Bytes)
    testBytes = bytes.fromhex(_testOutput)
    if outBytes == testBytes:
        print("Test Successful")
    else:
        print("Test Failed")

if __name__ == "__main__":
    solveChallenge02()
