""" Provides various ascii related functions to assist with the cryptopals
challenges. """

from util.bmanip import xor

# Dictionary of relative letter frequencies in standard text. All uppercase
# was converted to lowercase. Includes space. Does not include numbers or
# special characters (removed from samples). Taken from
# http://www.data-compression.com/english.html.
_letter_frequency_dict = {"a" : 0.0651738,
                          "b" : 0.0124248,
                          "c" : 0.0217339,
                          "d" : 0.0349835,
                          "e" : 0.1041442,
                          "f" : 0.0197881,
                          "g" : 0.0158610,
                          "h" : 0.0492888,
                          "i" : 0.0558094,
                          "j" : 0.0009033,
                          "k" : 0.0050529,
                          "l" : 0.0331490,
                          "m" : 0.0202124,
                          "n" : 0.0564513,
                          "o" : 0.0596302,
                          "p" : 0.0137645,
                          "q" : 0.0008606,
                          "r" : 0.0497563,
                          "s" : 0.0515760,
                          "t" : 0.0729357,
                          "u" : 0.0225134,
                          "v" : 0.0082903,
                          "w" : 0.0171272,
                          "x" : 0.0013692,
                          "y" : 0.0145984,
                          "z" : 0.0007836,
                          " " : 0.1918182}

def scoreBytesAsPlaintext(ba):
    """ Takes a bytes object, and creates a score for that object based on how
    likely it is that the bytes represent ASCII encoded english plaintext. This
    score is arbitrary and should only compared against other outputs from this
    function. A higher score means more likely to be english plaintext.
    Only examines alpha and spaces. Ignores numeric and special characters.
    Automatically returns 0 if any byte is greater than 0x7f
    """
    cumSum = 0.0
    for b in ba:
        # If outside of ascill text range, automatically return 0.
        if b > 0x7f:
            return 0
        cumSum += _letter_frequency_dict.get(chr(b).lower(), 0)
    return cumSum * 1000 / len(ba)

def calculateBestXoredWeight(b):
    """ Takes bytes as input. For each possible byte (0x00-0xff), performs an
    XOR of that byte with the input bytes, then runs the generated
    XOR through scoreBytesAsPlaintext. Returns the highest score and the byte
    that produced that score.
    """
    highScore = 0
    highByte = bytes([0])
    for i in range(0, 256):
        x = xor(b, bytes([i]))
        score = scoreBytesAsPlaintext(x)
        if score > highScore:
            highScore = score
            highByte = bytes([i])
    return (highByte, highScore)
