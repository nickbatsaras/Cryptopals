#!/usr/bin/python3

from cryptopals import RepeatingXOR
from cryptopals import HexXOR
from cryptopals import IsPlaintext
from cryptopals import StringToBinary
from cryptopals import HammingDistance
from cryptopals import Base64ToHex
from cryptopals import HexToAscii

DICTIONARY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=,./?'[]{}`|"

HEX = ""
THEX = ""

with open("06.txt") as FILE:
    for line in FILE:
        line = line.strip()
        HEX += Base64ToHex(line) + '\n'

HEX = HEX.strip()

HEXN = HEX.replace('\n', '')

for KEYSIZE in range(2, 41):
    # Transpose
    with open("transposed.txt", "w") as FILE:
        for i in range(0, 2*KEYSIZE, 2):
            for j in range(i, len(HEXN)-1, 2*KEYSIZE):
                FILE.write(HEXN[j])
                FILE.write(HEXN[j+1])
            FILE.write('\n')

    break
    with open("transposed.txt") as FILE:
        key = []
        for line in FILE:
            line = line.strip()

            MAX = 0
            MAXC = ''
            for c in DICTIONARY:
                IN2 = bytes(c*len(line), "ascii").hex()
                IN2 = IN2[:len(line)]

                OUT = HexXOR(line, IN2)
                OUT = HexToAscii(OUT)

                #print(IsPlaintext(OUT))
                if IsPlaintext(OUT) > MAX:
                    MAX = IsPlaintext(OUT)
                    MAXC = c

            key += MAXC

        if len(key) > 0:
            print(key, KEYSIZE)
