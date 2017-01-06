_inputString1 = "1c0111001f010100061a024b53535009181c"
_inputString2 = "686974207468652062756c6c277320657965"
_testOutput = "746865206b696420646f6e277420706c6179"

def fixedXor(a, b):
    """ Takes two bytearrays of the same length, XORs them together, and
    returns the result as a bytes object. """
    if (type(a) != bytes and type(a) != bytearray):
        raise TypeError("a is not a bytes object")
    if (type(b) != bytes and type(b) != bytearray):
        raise TypeError("b is not a bytes object")
    if len(a) != len(b):
        raise ValueError("a and b must be of the same length")
    b = bytes((i ^ j) for (i, j) in zip(a, b))
    return b

def solveChallenge02():
    """ Solves Cryptopals Challenge 02 """
    in1Bytes = bytes.fromhex(_inputString1)
    in2Bytes = bytes.fromhex(_inputString2)
    outBytes = fixedXor(in1Bytes, in2Bytes)
    testBytes = bytes.fromhex(_testOutput)
    if outBytes == testBytes:
        print("Test Successful")
    else:
        print("Test Failed")

if __name__ == "__main__":
    solveChallenge02()
