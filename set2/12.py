import string, random
from Crypto.Cipher import AES
from cryptopals    import AsciiToHex
from cryptopals    import Base64ToHex
from cryptopals    import HexToAscii
from cryptopals    import PKCS7

def RandomBytes(length):
    dictionary = string.ascii_letters + string.punctuation + string.digits
    key = "".join(random.SystemRandom().choice(dictionary) for x in range(length))

    return str.encode(key)

def encryption_oracle(plaintext, postfix):
    plaintext += postfix

    plaintext = PKCS7(plaintext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(bytes.fromhex(AsciiToHex(plaintext)))
    ciphertext = ciphertext.hex()

    return ciphertext

def detect_blocksize():
    blocksizes = [16, 24, 32, 64]

    for i in range(len(blocksizes)-1):
        prevcipher = encryption_oracle('A'*blocksizes[i],   POSTFIX)
        currcipher = encryption_oracle('A'*blocksizes[i+1], POSTFIX)

        if currcipher.count(prevcipher[0:blocksizes[i]]) == 1:
            return blocksizes[i]

def detect_ECB(ciphertext, blocksize=16):
    if ciphertext[0:2*blocksize] == ciphertext[2*blocksize:4*blocksize]:
        return True
    return False


KEY = RandomBytes(16)

BASE64POSTFIX = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
HEXPOSTFIX = Base64ToHex(BASE64POSTFIX)
POSTFIX = HexToAscii(HEXPOSTFIX)

BLOCKSIZE = detect_blocksize()

CIPHERTEXT = encryption_oracle('a' * 2 * BLOCKSIZE, POSTFIX)

print("Detected blocksize:\t%d bytes" % BLOCKSIZE)
if detect_ECB(CIPHERTEXT, BLOCKSIZE) == True:
    print("Detected ECB:\t\tTrue")

BLOCK = 'A' * (BLOCKSIZE-1)
DICTIONARY = {}

PLAINTEXT = ""

for i in string.ascii_letters + string.punctuation + string.digits + string.whitespace:
    DICTIONARY[encryption_oracle(BLOCK+i, POSTFIX)[0:BLOCKSIZE]] = BLOCK+i

for i in range(len(POSTFIX)):
    block = DICTIONARY[encryption_oracle(BLOCK, POSTFIX[i:])[0:BLOCKSIZE]]
    PLAINTEXT += block[len(block)-1]

print("\nUnknown String:\n\n" + PLAINTEXT)
