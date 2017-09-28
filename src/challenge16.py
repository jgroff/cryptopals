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
        # Prepend/append
        data = self.__prependBytes + data + self.__appendBytes
        data = padPkcs7(data, 16)
        return self.__aes.cbcEncrypt(data, self.__iv)

    def decryptAndLookForText(self, data):
        """ Decrypts the data and looks for the phrase ";admin=true;"
        Returns True if the phase is found, false if not.
        """
        dec = self.__aes.cbcDecrypt(data, self.__iv)
        if b";admin=true;" in dec:
            return True
        else:
            return False

def solveChallenge16():
    """ Solves Cryptopals Challenge 16 """
    # Flip a bit in the ciphertext of a block. That causes the block, when
    # decrypted, to be completely scrambled. However, in the next block,
    # the bit in the same position in the block gets flipped in the plain text
    # after decryption. This happens because the ciphertext is xored with
    # the decrypted ciphertext of the next block to get the plain text of the
    # next block. Neat.
    # What I want the decrypted text to look like is:
    #  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd
    # "comment1=cooking%20MCs;userdata=<GARBAGE>;admin=true;comment2=
    # ef0123456789abcdef0123456789abcd
    # %20like%20a%20pound%20of%20bacon"
    # I could be more messy and put the admin=true anywhere, but it's neater
    # to not overwrite any of the existing data.
    # It's generous that the end of the prepend bytes ends at a block.
    # So, what I want to put in is two blocks. The first is my editable block
    # and can contain whatever I want. The second block will have
    # ";admin=true" at the end of the block. However I can't enter ; and =
    # so we'll make it "3admin5true" instead, and we flip two bits total.
    # User input is AAAAAAAAAAAAAAAABBBBB3admin5true
    userBytes = b'AAAAAAAAAAAAAAAABBBBB3admin5true'
    enc = Challenge16Encryptor()
    ciphertext = enc.encrypt(userBytes)
    # Third block, flip bit 3 of byte 5 and byte 11
    ciphertext = bytearray(ciphertext)
    ciphertext[32+5] ^= 0x08
    ciphertext[32+11] ^= 0x08
    ciphertext = bytes(ciphertext)
    # See if we did this correctly.
    if (enc.decryptAndLookForText(ciphertext)):
        print("Found the correct text")
    else:
        print("Did not find the correct text.")


if __name__ == "__main__":
    solveChallenge16()
