from util.mcrypt import *

PREPEND_STRING = "comment1=cooking%20MCs;userdata="
APPEND_STRING = ";comment2=%20like%20a%20pound%20of%20bacon"


class Challenge16Encryptor(object):
    """ An encryptor object for helping with challenge 16. """

    def __init__(self):
        """ Initialize the object. """
        self.__aes = Aes(generateRandomAesKey())
        self.__prependBytes = PREPEND_STRING.encode()
        self.__appendBytes = APPEND_STRING.encode()
        self.__iv = bytes(16)

    def encrypt(self, data):
        """ Encrypts data according to the challenge 16 description.
            IV doesn't matter for this exercise so use an IV of all zeros.
        """
        # Remove any ; and = characters.
        data = data.replace(b';', b'')
        data = data.replace(b'=', b'')
        data = padPkcs7(data, 16)
        return self.__aes.cbcEncrypt(data, self.__iv)


def solveChallenge16():
    """ Solves Cryptopals Challenge 16 """
    # Flip a bit in the ciphertext of a block. That causes the block, when
    # decrypted, to be completely scrambled. However, in the next block,
    # the bit in the same position in the block gets flipped in the plain text
    # after decryption. This happens because the ciphertext is xored with
    # the decrypted ciphertext of the next block to get the plain text of the
    # next block. Neat.


    

if __name__ == "__main__":
    solveChallenge16()
