import os, string
from Crypto.Cipher import AES
from cryptopals    import Base64ToHex
from cryptopals    import HexToAscii
from cryptopals    import PKCS7

def encryption_oracle(key, plaintext, postfix):
    plaintext += postfix

    plaintext = PKCS7(plaintext)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    ciphertext = ciphertext.hex()

    return ciphertext

def detect_blocksize(key, postfix):
    blocksizes = [16, 24, 32, 64]

    for i in range(len(blocksizes)-1):
        prevcipher = encryption_oracle(key, 'A'*blocksizes[i],   postfix)
        currcipher = encryption_oracle(key, 'A'*blocksizes[i+1], postfix)

        if currcipher.count(prevcipher[0:blocksizes[i]]) == 1:
            return blocksizes[i]

def detect_ECB(ciphertext, blocksize):
    if ciphertext[0:2*blocksize] == ciphertext[2*blocksize:4*blocksize]:
        return True
    return False

def ByteAtATimeSimple(key, base64postfix):
    hexpostfix = Base64ToHex(base64postfix)
    postfix = HexToAscii(hexpostfix)

    blocksize = detect_blocksize(key, postfix)
    ciphertext = encryption_oracle(key, 'a' * 2 * blocksize, postfix)

    assert(detect_ECB(ciphertext, blocksize))

    inputtext = 'A' * (blocksize-1)
    dictionary = {}

    plaintext = ""

    for i in string.ascii_letters + string.punctuation + string.digits + string.whitespace:
        dictionary[encryption_oracle(key, inputtext+i, postfix)[0:blocksize]] = inputtext+i

    for i in range(len(postfix)):
        block = dictionary[encryption_oracle(key, inputtext, postfix[i:])[0:blocksize]]
        plaintext += block[len(block)-1]

    assert(plaintext == postfix)

    return plaintext


BASE64POSTFIX = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = os.urandom(16)

PLAINTEXT = ByteAtATimeSimple(KEY, BASE64POSTFIX)

print(PLAINTEXT)
