from base64 import b64encode, b64decode

_inputString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
_testString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

def solveChallenge01():
    """ Solves Cryptopals Challenge 01 """
    inBytes = bytes.fromhex(_inputString)
    encodedBytes = b64encode(inBytes)
    testBytes = _testString.encode()
    if encodedBytes == testBytes:
        print("Conversion Successful")
    else:
        print("Conversion Failed")

if __name__ == "__main__":
    solveChallenge01()
