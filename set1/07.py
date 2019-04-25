#!/usr/bin/env python3

from cryptopals import Base64ToHex
from Crypto.Cipher import AES

KEY = b"YELLOW SUBMARINE"
CIPHER = AES.new(KEY, AES.MODE_ECB)

HEX = ""

with open("07.txt") as FILE:
    for line in FILE:
        line = line.strip()
        HEX += Base64ToHex(line)

TEXT = CIPHER.decrypt(bytes.fromhex(HEX))

print(TEXT.decode("ascii"))
