from base64 import b64decode
from util.mcrypt import Aes

_keyString = "YELLOW SUBMARINE"

def solveChallenge07():
    """ Solves Cryptopals Challenge 07 """
    # Import the data and place it into a buffer.
    f = open("../data/data07.txt", 'r')
    b64buf = f.read()
    f.close()
    rawData = b64decode(b64buf)
    # Turn the key into bytes
    key = _keyString.encode()
    # Decrypt the data
    aes = Aes(key)
    decrypted = aes.ecbDecrypt(rawData)
    # Print it.
    print(decrypted.decode())

if __name__ == "__main__":
    solveChallenge07()
