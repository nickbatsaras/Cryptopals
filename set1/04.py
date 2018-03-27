#!/usr/bin/python3

from cryptopals import HexXOR
from cryptopals import HexToAscii

DICTIONARY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def NumOfLetters(s):
    chrs = 0
    for c in s:
        if c.isalpha():
            chrs += 1

    return chrs

secret = ""

txt = open("04.txt")

for IN1 in txt:
    IN1 = IN1.strip()

    for c in DICTIONARY:
        IN2 = bytes(c*len(IN1), "ascii").hex()
        IN2 = IN2[:len(IN1)]

        OUT = HexXOR(IN1, IN2)

        try:
            plaintext = HexToAscii(OUT)
        except:
            break
        else:
            plaintext = plaintext.strip()
            num = NumOfLetters(plaintext.replace(' ', ''))
            if num > 0.95 * len(plaintext.replace(' ', '')):
                secret = plaintext.strip(' ')

txt.close()
print(secret)
