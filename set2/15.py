#!/usr/bin/env python3

from cryptopals import PKCS7Validate

IN1 = "ICE ICE BABY\x04\x04\x04\x04"
IN2 = "ICE ICE BABY\x05\x05\x05\x05"

if PKCS7Validate(IN1):
    print("PASS: " + IN1)
else:
    print("FAIL")
