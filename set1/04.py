#!/usr/bin/python3

from cryptopals import HexXOR
from cryptopals import HexToAscii
from cryptopals import IsPlaintext

DICTIONARY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

SECRET = ""
DONE = False

FILE = open("04.txt")

for IN1 in FILE:
    IN1 = IN1.strip()

    for c in DICTIONARY:
        IN2 = bytes(c*len(IN1), "ascii").hex()
        IN2 = IN2[:len(IN1)]

        OUT = HexXOR(IN1, IN2)
        try:
            OUT = HexToAscii(OUT)
        except:
            continue

        if IsPlaintext(OUT):
            SECRET = OUT.strip()
            DONE = True
            break

    if DONE:
        break

FILE.close()

print(SECRET)
