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

def encryption_oracle(plaintext, key):
    base64postfix = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""
    hexpostfix = Base64ToHex(base64postfix)
    postfix = HexToAscii(hexpostfix)

    plaintext += postfix

    plaintext = PKCS7(plaintext)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(bytes.fromhex(AsciiToHex(plaintext)))
    ciphertext = ciphertext.hex()

    return ciphertext

##
# Step 1
##
def detect_blocksize():
    blocksizes = [16, 24, 32, 64]

    for i in range(len(blocksizes)-1):
        prevcipher = encryption_oracle('A'*blocksizes[i], KEY)
        currcipher = encryption_oracle('A'*blocksizes[i+1], KEY)

        if currcipher.count(prevcipher[0:blocksizes[i]]) == 1:
            print("Detected blocksize: %d bytes" % blocksizes[i])
            return blocksizes[i]

KEY = RandomBytes(16)
