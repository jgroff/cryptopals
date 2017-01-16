from base64 import b64decode
from util.bmanip import xor, calcHammDist
from util.asciifunc import calculateBestXoredWeight

def solveChallenge06():
    """ Solves Cryptopals Challenge 06 """
    # Import the data and place it into a buffer.
    f = open("../data/data06.txt", 'r')
    b64buf = f.read()
    f.close()
    rawData = b64decode(b64buf)
    # First, guess the keysize
    bestKeysize = 0
    bestIoc = 999
    for ks in range (2, 41):
        print("Trying Keysize %d" % (ks))
        # Go ahead and iterate over all the data, there's not that much.
        iocs = []
        for i in range(0, len(rawData), ks):
            for j in range(i, len(rawData) - ks, ks):
                a = rawData[i : i + ks]
                b = rawData[j : j + ks]
                normh = calcHammDist(a, b) * 1.0 / ks
                iocs.append(normh)
        ioc = sum(iocs, 1.0) / len(iocs)
        if ioc < bestIoc:
            bestIoc = ioc
            bestKeysize = ks
    print("The keysize has been determined to be %d" % (bestKeysize,))
    # Keysize has been guessed. Break the data into keysize sized blocks
    # and attempt to find the byte used for each block.
    key = bytearray()
    for i in range(bestKeysize):
        block = rawData[i : : bestKeysize]
        b, s = calculateBestXoredWeight(block)
        key.extend(b)
    key = bytes(key)
    print("The key is guessed as: %s" % (key,))

    # The key has been calculated. Decrypt the entire thing.
    decrypted = xor(key, rawData)
    print("")
    print("The decrypted text is:")
    print(decrypted.decode())



if __name__ == "__main__":
    solveChallenge06()
