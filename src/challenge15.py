from util.mcrypt import *

def solveChallenge15():
    """ Solves Cryptopals Challenge 15 """
    # The funny part is I already implemented this from previous
    # challenges. I'm starting to think I was making them harder than they
    # should be.
    s = "YELLOW SUBMARINE"
    b = s.encode()
    n = 20
    p = padPkcs7(b, n)
    print(p)
    p = p + b'\x02'
    print(p)
    try:
        p = unpadPkcs7(p, 20)
        print("Oops, this should throw")
    except ValueError:
        print("Yep threw an exception")

    # More test with CBC this time.
    aes = Aes(generateRandomAesKey())
    IV = generateRandomBytes(16)
    rawData = "abcdefghijklmnop".encode()
    encData = aes.cbcEncrypt(rawData, IV)
    decData = aes.cbcDecrypt(encData, IV)
    print(decData)
    print(unpadPkcs7(decData, 16))

    rawData = "ijklmnop".encode()
    encData = aes.cbcEncrypt(rawData, IV)
    decData = aes.cbcDecrypt(encData, IV)
    print(decData)
    print(unpadPkcs7(decData, 16))

if __name__ == "__main__":
    solveChallenge15()
