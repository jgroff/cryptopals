import re

from util.mcrypt import *

def parsekv(inputString):
    """ k=v parsing routine. Takes input such as 
        foo=bar&baz=qux&zap=zazzle
        and return a dictionary, with entries like
        d[foo] = bar, d[baz] = qux etc.
        Will throw an exception if there is not exactly one equals
        sign between each instance of an ampersand (or before/after
        for the start/end ampersands) Otherwise is pretty leiniant.
    """
    mDict = dict()
    parts = inputString.split('&')
    for item in parts:
        if (item.count('=') != 1):
            raise ValueError("Need a singular = sign in str.   %s" % (item, ))
        key, value = item.split('=')
        # If we can convert the string value to an int, great, otherwise
        # leave it as a string.
        try:
            mDict[key] = int(value)
        except ValueError:
            mDict[key] = value
    return mDict

def profileFor(emailAddress):
    """ Produces a user profile encoded in a k=v format """
    # Eat the encoding metacharacters.
    emailAddress = emailAddress.replace("&", "")
    emailAddress = emailAddress.replace("=", "")
    # Extremely basic check on validity of the email address.
    if not re.match(r"[^@]+@[^@]+\.[^@]+", emailAddress):
        return ""
    return "email=%s&uid=10&role=user" % (emailAddress)

class Challenge13Encryptor(object):
    """ An encryptor object for helping with challenge 13 """

    def __init__(self):
        """ Initialize the encryptor. """
        self.__aes = Aes(generateRandomAesKey())
    
    def profileForEncrypt(self, emailAddress):
        """ Uses profileFor and encrypts it using ECB """
        kvstring = profileFor(emailAddress)
        # Turn the string into bytes
        kvbytes = kvstring.encode()
        # Encrypt it.
        data = padPkcs7(kvbytes, 16)
        return self.__aes.ecbEncrypt(data)
    
    def decrypt(self, b):
        """ Decrypt the given bytes using the key saved. """
        decrypted = self.__aes.ecbDecrypt(b)
        return unpadPkcs7(decrypted, 16)

def solveChallenge13():
    """ Solves Cryptopals Challenge 13 """
    # The goal as stated on the webpage was a little unclear to me.
    # I have interpreted it as: We have a function and the ONLY thing we
    # can offer it is an email address. It returns an encrypted chunk of
    # data. We need to give it enough data in enough ways that we can
    # sew together chucks and/or blocks to get us a "role=admin" string.
    # This makes sense according to "using only the user input" and the
    # "cyphertexts themselves". We can give our own input to the
    # encryption function, and we can mess with the encrypted data.
    # The decrypt function is there only to check our work. It will
    # not be used in the process of creating this "role=admin" string
    #
    # So!
    # ECB. Stateless 16-byte blocks. This should be straightforward.
    # Because we can control, more or less, single blocks, and we know
    # the block size, we can align things!
    # So here's what we need: at the end of the a block, we need to align
    # "...role=" right at the end of it.
    # Separately, we need to have "admin" at the start of another block. 
    # This way when the two blocks are set next to each other, it unencrypts
    # into "role=admin"
    # First question - what do we feed the profileForEncrypt to get "role="
    # at the end?
    # email=&uid=10&role= is 19 bytes. To get to a multiple block size
    # an email address of length 32-19 = 13 is required. "xxx@yyyyy.com"
    # suffices.
    # Second question. How do we get "admin" at the start of a second block
    # and leave it by itself as well? There are surely better ways to do this
    # but with what we've been given, just make certain there's a block
    # that contains nothing but "admin" and 11 hex bytes of dec value 11.
    # email=abcdefghijadmin(x11*11)@here.com
    # i.e., admin pkcs7 padded.
    # Note that a proper email parser would probably toss this out immediately
    enc = Challenge13Encryptor()
    email1 = "xxx@yyyyy.com"
    email2 = "abcdefghijadmin" + "\x0B"*11 + "@here.com"
    enc1 = enc.profileForEncrypt(email1)
    enc2 = enc.profileForEncrypt(email2)
    # Combine the first two blocks of encrypted 1 with
    # the second block of encrypted 2.
    combined = enc1[0:32] + enc2[16:32]
    decBytes = enc.decrypt(combined)
    parsed = parsekv(decBytes.decode())
    print(parsed)

if __name__ == "__main__":
    solveChallenge13()
