#!/usr/bin/env python3

from cryptopals import HexXOR
from cryptopals import HexToAscii
from cryptopals import IsPlaintext

IN1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
DICTIONARY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

SECRET = ""

for c in DICTIONARY:
    IN2 = bytes(c*len(IN1), "ascii").hex()
    IN2 = IN2[:len(IN1)]

    OUT = HexXOR(IN1, IN2)
    OUT = HexToAscii(OUT)

    if IsPlaintext(OUT):
        SECRET = OUT
        break

print(SECRET)
