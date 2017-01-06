from itertools import cycle

def xor(a, b):
    """ Takes two bytes objects, XORs them together, and returns the result as
        a bytes object.
        If one of the arrays is longer than the other, this function will
        repeat the shorter one until the longer is xored.
    """
    if (type(a) != bytes and type(a) != bytearray):
        raise TypeError("a is not a bytes object")
    if (type(b) != bytes and type(b) != bytearray):
        raise TypeError("b is not a bytes object")
    if len(a) < 1 or len(b) < 1:
        raise ValueError("Length of byte arrays must be greater than 0")

    # Make b be the one of greater length
    if len(a) > len(b):
        b, a = a, b
    out = bytes((i ^ j) for (i, j) in zip(cycle(a), b))
    return out
