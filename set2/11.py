import string, random
from Crypto.Cipher import AES
from cryptopals    import AsciiToHex
from cryptopals    import PKCS7
from cryptopals    import EncryptCBC

def RandomBytes(length):
    dictionary = string.ascii_letters + string.punctuation + string.digits
    key = "".join(random.SystemRandom().choice(dictionary) for x in range(length))

    return str.encode(key)

def encryption_oracle(plaintext, blocksize=16):
    modes = ['ECB', 'CBC']

    key = RandomBytes(blocksize)

    fbytes = RandomBytes(random.randint(5, 10))
    bbytes = RandomBytes(random.randint(5, 10))

    plaintext = fbytes.decode() + plaintext + bbytes.decode()

    mode = random.choice(modes)

    if mode == 'ECB':
        plaintext = PKCS7(plaintext)
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(bytes.fromhex(AsciiToHex(plaintext)))
        ciphertext = ciphertext.hex()
    else:
        dictionary = string.digits + 'ABCDEF'
        iv = "".join(random.SystemRandom().choice(dictionary) for x in range(blocksize*2))
        ciphertext = EncryptCBC(plaintext, key, blocksize, iv)

    return ciphertext, mode

def detection_oracle(ciphertext, blocksize=16):
    for start in range(0, len(ciphertext)-blocksize, blocksize):
        pattern = ciphertext[start:start+blocksize]
        if ciphertext.count(pattern) > 1:
            return 'ECB'
    return 'CBC'

##
#
# The rationale behind the 43-byte input text
# -------------------------------------------
#
# * We need 32 bytes, untouched, to get a repetition with blocksize 16
#
# Some bytes will be prepended & appended
# * The total number of bytes for the input text, will be 64, after PKCS7
#   padding
# * The prepended bytes will be from the random bytes of the oracle function
# * The appended bytes will be from the random bytes of the oracle function and
#   from the padding
#
#                       +--------------------------------------+
#     input text bytes: |    16     |      32      |    16     |
#                       +--------------------------------------+
#                             ^                          ^
#                      random & input text        random & pad
#
# * The worst case for the prepended bytes, is to add 5 random bytes. This
#   results in "stealing" 11 bytes from our input text. This means we need at
#   least 32+11=43 bytes of input text
# * We don't really care about the appended bytes. Some will be random and
#   some will be the result of padding. We hit a repetition no matter what
#
##

FAILS      = 0
ITERATIONS = 10000

for i in range(ITERATIONS):
    ciphertext, mode = encryption_oracle('0'*43)

    if detection_oracle(ciphertext) != mode:
        FAILS += 1

print("Iterations:\t%d\nPasses:\t\t%d\nFails:\t\t%d" 
        % (ITERATIONS, ITERATIONS-FAILS, FAILS))
