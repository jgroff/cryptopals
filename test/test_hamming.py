import sys
sys.path.append("../src/")
from util.bmanip import calcHammDist

testString1 = "this is a test"
testString2 = "wokka wokka!!!"

b1 = testString1.encode()
b2 = testString2.encode()

dist = calcHammDist(b1, b2)

if (dist == 37):
    print("Test Passed")
else:
    print("Test Failed")
