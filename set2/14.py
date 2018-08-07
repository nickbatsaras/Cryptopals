from Crypto.Cipher import AES
from cryptopals    import PKCS7
from cryptopals    import HexToAscii
from cryptopals    import Base64ToHex
from cryptopals    import RandomString
from random        import randint
from os            import urandom
from string        import ascii_letters, punctuation, digits, whitespace

def encryption_oracle(key, plaintext, postfix):
    plaintext = PREFIX + plaintext + postfix

    plaintext = PKCS7(plaintext)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

def ByteAtATimeHarder(key, base64postfix):
    hexpostfix = Base64ToHex(base64postfix)
    postfix = HexToAscii(hexpostfix)

    blocksize = 16

    flag = True
    extra_bytes = 0
    block_start = 1024
    while flag:
        inputtext = 'A' * (3 * blocksize - extra_bytes)

        ciphertext = encryption_oracle(key, inputtext, postfix)

        for index in range(0, len(ciphertext)-blocksize, blocksize):
            if index > block_start:
                flag = False
                break
            pattern = ciphertext[index:index+blocksize]
            if ciphertext.count(pattern) > 1:
                block_start = index
                break

        extra_bytes += 1

    dictionary = {}
    inputtext = 'A' * (3 * blocksize - extra_bytes + 1)
    for i in ascii_letters + punctuation + digits + whitespace:
        start = block_start+blocksize
        end = block_start+2*blocksize
        dictionary[encryption_oracle(key, inputtext+i, postfix)[start:end]] = inputtext+i

    plaintext = ""
    for i in range(len(postfix)):
        start = block_start+blocksize
        end = block_start+2*blocksize
        block = dictionary[encryption_oracle(key, inputtext, postfix[i:])[start:end]]
        plaintext += block[len(block)-1]

    assert(plaintext == postfix)

    return plaintext


BASE64POSTFIX = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = urandom(16)
PREFIX = RandomString(randint(1, 100))

PLAINTEXT = ByteAtATimeHarder(KEY, BASE64POSTFIX)

print(PLAINTEXT)
