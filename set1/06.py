#!/usr/bin/python3

from cryptopals import Base64ToHex
from cryptopals import HexXOR
from cryptopals import IsPlaintext
from cryptopals import HexToAscii

DICTIONARY  = "0123456789"
DICTIONARY += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DICTIONARY += "abcdefghijklmnopqrstuvwxyz"
DICTIONARY += "~!@#$%^&*()_+-={}[]:'|<>,.?/ "

HEX = ""
THEX = ""

with open("06.txt") as FILE:
    for line in FILE:
        line = line.strip()
        HEX += Base64ToHex(line) + '\n'

HEXN = HEX.strip().replace('\n', '')

START = 2
END = 40
print("\n\tKeysize range: [%d, %d]\n" % (START, END))

for KEYSIZE in range(2, 41):
    # Transpose
    with open("transposed.txt", "w") as FILE:
        for i in range(0, 2*KEYSIZE, 2):
            for j in range(i, len(HEXN)-1, 2*KEYSIZE):
                FILE.write(HEXN[j])
                FILE.write(HEXN[j+1])
            FILE.write('\n')

    with open("transposed.txt") as FILE:
        key = []
        for line in FILE:
            line = line.strip()

            for c in DICTIONARY:
                IN2 = bytes(c*len(line), "ascii").hex()
                IN2 = IN2[:len(line)]

                OUT = HexXOR(line, IN2)
                OUT = HexToAscii(OUT)

                if IsPlaintext(OUT, 0.85):
                    key += c

        if len(key) == KEYSIZE:
            print("\tPossible key: \"" + ''.join(key) + '\"\n')

exit()

KEY = "Terminator X: Bring the noise"

KEYHEX = ""

for c in KEY:
    r = format(ord(c), 'x')
    if len(r) == 1:
        KEYHEX += '0' + r
    else:
        KEYHEX += r

HEX = HEX.replace('\n', '')

for i in range(0, len(HEX)//len(KEYHEX)):
    print(HexToAscii(HexXOR(HEX[i*len(KEYHEX):(i+1)*len(KEYHEX)], KEYHEX)))

exit()
