from util.asciifunc import calculateBestXoredWeight
from util.bmanip import xor

def solveChallenge04():
    """ Solves Cryptopals Challenge 04 """
    # Read in the file.
    f = open("../data/data04.txt", 'r')
    lines = []
    while True:
        line = f.readline()
        if line == "":
            break
        lines.append(bytes.fromhex(line.strip()))
    # Determine which line in file has the best score and what bytes.
    bestLine = 0
    bestScore = 0
    bestByte = bytes([0])
    for i in range(len(lines)):
        (highByte, highScore) = calculateBestXoredWeight(lines[i])
        if highScore > bestScore:
            bestLine = i
            bestScore = highScore
            bestByte = highByte
    # Print the best line decoded
    print("Line %d had the best score of %.2f using byte 0x%x" %
          (bestLine, bestScore, bestByte[0]))
    decBytes = xor(lines[bestLine], bestByte)
    print("Decoded String: %s" % (decBytes.decode()))
    
if __name__ == "__main__":
    solveChallenge04()
