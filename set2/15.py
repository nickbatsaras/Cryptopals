from string     import printable
from cryptopals import PKCS7

def PKCS7Validate(plaintext):
    plaintext = list(plaintext)
    for i in range(len(plaintext)):
        if plaintext[i] not in printable:
            if plaintext[i] == '\x04':
                plaintext[i] = ""
            else:
                raise Exception("Invalid PKCS7 padding")
    return "".join(plaintext)


IN1 = "ICE ICE BABY\x04\x04\x04\x04"
IN2 = "ICE ICE BABY\x05\x05\x05\x05"

if PKCS7Validate(IN1):
    print("PASS: " + IN1)
else:
    print("FAIL")
