from util.mcrypt import isEcbEncrypted
from util.bmanip import xor, calcHammDist
from util.asciifunc import calculateBestXoredWeight

def solveChallenge08():
    """ Solves Cryptopals Challenge 08 """
    # Import the data and place it into a buffer of lines (turn hex into bytes)
    lines = []
    f = open("../data/data08.txt", 'r')
    while True:
        line = f.readline()
        if line == "":
            break
        lines.append(bytes.fromhex(line.strip()))
    f.close()

    # Determine which line is most likely to be ECB encrypted.
    for i in range(len(lines)):
        line = lines[i]
        if isEcbEncrypted(line):
            ecbLine = line
            print("Found ECB Encrypted Line: %d" % (i,))
    

if __name__ == "__main__":
    solveChallenge08()
