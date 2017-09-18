import random
from util.mcrypt import Aes, padPkcs7, isEcbEncrypted, \
                        generateRandomBytes, \
                        generateRandomAesKey

def encryptRandomly(data):
    """ Encrypts data in a random fashion as directed in challenge 11 text """
    key = generateRandomAesKey()
    aes = Aes(key)
    prepend = generateRandomBytes(random.randint(5, 10))
    append = generateRandomBytes(random.randint(5, 10))
    data = prepend + data + append
    data = padPkcs7(data, 16)
    choice = random.randint(0, 1)
    if choice == 0:
        encData = aes.ecbEncrypt(data)
        print("Black box picked ECB")
    else:
        iv = generateRandomBytes(16)
        encData = aes.cbcEncrypt(data, iv)
        print("Black box picked CBC")
    return encData



def solveChallenge11():
    """ Solves Cryptopals Challenge 11 """
    # Load test data. The assumption here is that WE have control
    # over the test data, so it's just a bunch of A's repeated.
    f = open("../data/data11.txt", 'r')
    rawData = f.read().encode()
    f.close()
    numTrials = 10
    for _ in range(numTrials):
        encData = encryptRandomly(rawData)
        if isEcbEncrypted(encData):
            print("Detector thinks this is ECB")
        else:
            print("Detector thinks this is CBC")

if __name__ == "__main__":
    solveChallenge11()
