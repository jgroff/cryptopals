from util.mcrypt import padPkcs7

def solveChallenge09():
    """ Solves Cryptopals Challenge 09 """
    # Really all this does is just test my implementation of PKCS#7 padding.
    s = "YELLOW SUBMARINE"
    b = s.encode()
    n = 20
    p = padPkcs7(b, n)
    print(p)

    s = "YELLOW SUBMARINE"
    b = s.encode()
    n = 24
    p = padPkcs7(b, n)
    print(p)
    
    s = "YELLOW SUBMARINE"
    b = s.encode()
    n = 16
    p = padPkcs7(b, n)
    print(p)

    s = "Pizza Hut"
    b = s.encode()
    n = 20
    p = padPkcs7(b, n)
    print(p)

    s = "Now is time to go"
    b = s.encode()
    n = 23
    p = padPkcs7(b, n)
    print(p)

    s = "Jumping"
    b = s.encode()
    n = 3
    p = padPkcs7(b, n)
    print(p)

if __name__ == "__main__":
    solveChallenge09()
