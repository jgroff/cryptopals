import sys
sys.path.append("../src/")
from binascii import hexlify
from util.mcrypt import *

# Lets just test to see how this works...

S = "abcdefghijklmnop0123456789ABCDEFnnnnnnnnnnnnnnnn".encode()
KEY = "YELLOW SUBMARINE".encode()
IV = bytes(16)

aes = Aes(KEY)
enc = aes.cbcEncrypt(S, IV)
dec = aes.cbcDecrypt(enc, IV)
print(hexlify(dec))

encBitflip = bytearray(enc)
encBitflip[0] ^= 0x80
dec = aes.cbcDecrypt(bytes(encBitflip), IV)
print(hexlify(dec))