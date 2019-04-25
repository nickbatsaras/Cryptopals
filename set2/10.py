#!/usr/bin/env python3

from cryptopals import EncryptCBC
from cryptopals import DecryptCBC
from cryptopals import Base64ToHex

KEY = b"YELLOW SUBMARINE"
BLOCKSIZE = 16
IV = '\x00' * BLOCKSIZE

#PLAINTEXT = """This is a TEST. this is another test,
#and yet another one"""
#
#CIPHERTEXT = EncryptCBC(PLAINTEXT, KEY, BLOCKSIZE, IV)
#
#if DecryptCBC(CIPHERTEXT, KEY, BLOCKSIZE, IV) == PLAINTEXT:
#    print("PASS")
#else:
#    print("FAIL")

HEX = ""
with open("10.txt") as FILE:
    for line in FILE:
        line = line.strip()
        HEX += Base64ToHex(line)

PLAINTEXT = DecryptCBC(HEX, KEY, BLOCKSIZE, IV)

print(PLAINTEXT)
