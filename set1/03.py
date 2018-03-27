#!/usr/bin/python3

from cryptopals import HexXOR
from cryptopals import HexToAscii

IN1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
DICTIONARY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def NumOfLetters(s):
    chrs = 0
    for c in s:
        if c.isalpha():
            chrs += 1

    return chrs

lcount = 0
secret = ""

for c in DICTIONARY:
    IN2 = bytes(c*len(IN1), "ascii").hex()
    IN2 = IN2[:len(IN1)]

    OUT = HexXOR(IN1, IN2)

    plaintext = HexToAscii(OUT)

    num = NumOfLetters(plaintext)
    if num > lcount:
        lcount = num
        secret = plaintext

print(secret)
