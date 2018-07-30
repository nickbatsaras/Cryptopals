import string
import random
from Crypto.Cipher import AES
from cryptopals import AsciiToHex
from cryptopals import PKCS7
from cryptopals import EncryptCBC

def RandomBytes(length):
    dictionary = string.ascii_letters + string.punctuation + string.digits
    key = "".join(random.SystemRandom().choice(dictionary) for x in range(length))

    return str.encode(key)

def encryption_oracle(plaintext):
    length = random.randint(5, 10)
    rbytes = RandomBytes(length)
    plaintext = rbytes.decode() + plaintext

    length = random.randint(5, 10)
    rbytes = RandomBytes(length)
    plaintext += rbytes.decode()

    key = RandomBytes(16)

    if random.randint(0, 1) == 0:
        print("Real: ECB")
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = PKCS7(plaintext)
        ciphertext = cipher.encrypt(bytes.fromhex(AsciiToHex(plaintext)))
        ciphertext = ciphertext.hex()
    else:
        print("Real: CBC")
        dictionary = string.digits + 'ABCDEF'
        iv = "".join(random.SystemRandom().choice(dictionary) for x in range(16*2))
        ciphertext = EncryptCBC(plaintext, key, 16, iv)

    return ciphertext

def detection_oracle(ciphertext):
        for start in range(0, len(ciphertext)-16, 16):
            pattern = ciphertext[start:start+16]
            if ciphertext.count(pattern) > 1:
                print("Guess: ECB Mode")
                return
        print("Guess: CBC Mode")

detection_oracle(encryption_oracle('0'*48))
