from base64 import b64decode
from util.mcrypt import Aes

KEY = "YELLOW SUBMARINE"
IV = bytes([0]*16)

def solveChallenge10():
    """ Solves Cryptopals Challenge 10 """
    # Import the data and place it into a buffer.
    f = open("../data/data10.txt", 'r')
    b64buf = f.read()
    f.close()
    rawData = b64decode(b64buf)
    # Attempt to decrypt it.
    key = KEY.encode()
    aes = Aes(key)
    decryptedData = aes.cbcDecrypt(rawData, IV)
    decryptedString = decryptedData.decode()
    print(decryptedString)

if __name__ == "__main__":
    solveChallenge10()
