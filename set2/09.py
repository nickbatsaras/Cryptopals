#!/usr/bin/python3

from cryptopals import PKCS7

IN = "YELLOW SUBMARINE"
OUT = "YELLOW SUBMARINE\x04\x04\x04\x04"

if PKCS7(IN, 20) == OUT:
    print("PASS")
else:
    print("FAIL")
