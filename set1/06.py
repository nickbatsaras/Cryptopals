#!/usr/bin/env python3

from cryptopals import Base64ToHex
from cryptopals import HexXOR
from cryptopals import IsPlaintext
from cryptopals import HexToAscii
from cryptopals import AsciiToHex

DICTIONARY  = "0123456789"
DICTIONARY += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DICTIONARY += "abcdefghijklmnopqrstuvwxyz"
DICTIONARY += "~!@#$%^&*()_+-={}[]:'|<>,.?/ "

HEX = ""
KEY = ""

with open("06.txt") as FILE:
    for line in FILE:
        line = line.strip()
        HEX += Base64ToHex(line)

START, END = 2, 40

print("\n\tKeysize range: [%d, %d]\n" % (START, END))

for KEYSIZE in range(START, END+1):
    # Transpose
    with open("transposed.txt", "w") as FILE:
        for i in range(0, 2*KEYSIZE, 2):
            for j in range(i, len(HEX)-1, 2*KEYSIZE):
                FILE.write(HEX[j])
                FILE.write(HEX[j+1])
            FILE.write('\n')

    with open("transposed.txt") as FILE:
        key = ""
        for line in FILE:
            line = line.strip()

            for c in DICTIONARY:
                IN2 = bytes(c*len(line), "ascii").hex()
                IN2 = IN2[:len(line)]

                OUT = HexXOR(line, IN2)
                try:
                    OUT = HexToAscii(OUT)
                except:
                    continue

                if IsPlaintext(OUT, 0.85):
                    key += c

        if len(key) == KEYSIZE:
            print("\tPossible key: \"" + key + '\"\n')
            KEY = key
            break

KEYHEX = AsciiToHex(KEY)

index = 0
for i in range(0, len(HEX), 2):
    c = HexToAscii(HexXOR(HEX[i]+HEX[i+1], KEYHEX[index]+KEYHEX[index+1]))

    print(c, end='')

    index += 2
    if index >= len(KEYHEX):
        index = 0
