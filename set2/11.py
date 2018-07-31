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


CIPHERTEXT, MODE = encryption_oracle('0'*48)

if detection_oracle(CIPHERTEXT) == MODE:
    print("PASS")
else:
    print("FAIL")
