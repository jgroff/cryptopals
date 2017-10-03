from base64 import b64decode
from util.mcrypt import *

_STRING = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

def solveChallenge18():
    """ Solves Cryptopals Challenge 18 """
    # In this case, we're implementing the CTR stream cipher mode.
    # The goal of this is to test our implementation, starting with
    # the base64 string above.
    testBytes = b64decode(_STRING)
    aes = Aes(b"YELLOW SUBMARINE")
    plainBytes = aes.ctrEncrypt(testBytes, 0)
    print(plainBytes)

    string1 = b"This is the time for us to think about many things."
    string2 = b"Look at this stuff, isn't it neat? Wouldn't you say my collection's complete?"
    enc1 = aes.ctrEncrypt(string1, 12345)
    enc2 = aes.ctrEncrypt(string2, 4929492)
    dec1 = aes.ctrEncrypt(enc1, 12345)
    dec2 = aes.ctrEncrypt(enc2, 4929492)
    print(dec1)
    print(dec2)

if __name__ == "__main__":
    solveChallenge18()
