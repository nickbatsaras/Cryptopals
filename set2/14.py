from Crypto.Cipher import AES
from cryptopals    import PKCS7
from cryptopals    import HexToAscii
from cryptopals    import Base64ToHex
from cryptopals    import RandomString
from random        import randint
from os            import urandom
from string        import ascii_letters, punctuation, digits, whitespace

def encryption_oracle(key, plaintext, prefix, postfix):
    plaintext = prefix + plaintext + postfix

    plaintext = PKCS7(plaintext)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

##
#
# This function answers 2 questions:
#
#   1) Which is the index of the first block containing no prefix bytes
#   2) How many bytes from input-text overflow blocksize
#
# We end up having the following scheme (in most cases):
#
#                 +------------------------------------------------+
#     input text: | prefix & input | input | input & postfix & pad |
#                 +------------------------------------------------+
#                                  ^           ^
#                             block_start   overflown
#                                            input
#
# The goal is to remove the overflown input bytes and know the position of the
# last block containing no prefix bytes:
#
#                 +----------------------------------------+
#     input text: | prefix & input | input | postfix & pad |
#                 +----------------------------------------+
#                                  ^
#                             block_start
#
#
##
def InputConfig(key, blocksize, prefix, postfix):
    flag = True
    extra_bytes = 0
    block_start = 1024
    while flag:
        inputtext = 'A' * (3 * blocksize - extra_bytes)
        ciphertext = encryption_oracle(key, inputtext, prefix, postfix)

        for index in range(0, len(ciphertext)-blocksize, blocksize):
            if index > block_start:
                flag = False
                break
            pattern = ciphertext[index:index+blocksize]
            if ciphertext.count(pattern) > 1:
                block_start = index
                break

        extra_bytes += 1

    return block_start, extra_bytes - 1


def ByteAtATimeHarder(key, prefix, base64postfix):
    hexpostfix = Base64ToHex(base64postfix)
    postfix = HexToAscii(hexpostfix)

    blocksize = 16

    block_start, extra_bytes = InputConfig(key, blocksize, prefix, postfix)

    dictionary = {}
    inputtext = 'A' * (3 * blocksize - extra_bytes)
    for i in ascii_letters + punctuation + digits + whitespace:
        dictionary[encryption_oracle(key, inputtext+i, prefix, postfix)\
                [block_start+blocksize:block_start+2*blocksize]] = inputtext+i

    plaintext = ""
    for i in range(len(postfix)):
        block = dictionary[encryption_oracle(key, inputtext, prefix, postfix[i:])\
                [block_start+blocksize:block_start+2*blocksize]]
        plaintext += block[len(block)-1]

    assert(plaintext == postfix)

    return plaintext


BASE64POSTFIX = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = urandom(16)
PREFIX = RandomString(randint(1, 100))

PLAINTEXT = ByteAtATimeHarder(KEY, PREFIX, BASE64POSTFIX)

print(PLAINTEXT)
