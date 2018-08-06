import string, random
from Crypto.Cipher import AES
from cryptopals    import PKCS7

def RandomBytes(length):
    dictionary = string.ascii_letters + string.punctuation + string.digits
    key = "".join(random.SystemRandom().choice(dictionary) for x in range(length))

    return str.encode(key)

def KVparse(string):
    kv = {}
    string = string.split('&')
    for s in string:
        s = s.split('=')
        kv[s[0]] = s[1]
    return kv

def profile_for(email):
    return "email="+email+"&uid=10&role=user"


KEY = RandomBytes(16)
CIPHER = AES.new(KEY, AES.MODE_ECB)

EMAIL = "batsaras@csd.uoc.gr"

PLAINUSER  = profile_for(EMAIL)
PLAINUSER  = PKCS7(PLAINUSER)
CIPHERUSER = CIPHER.encrypt(PLAINUSER)

PLAINADMIN  = profile_for(EMAIL).replace("user", "admin")
PLAINADMIN  = PKCS7(PLAINADMIN)
CIPHERADMIN = CIPHER.encrypt(PLAINADMIN)

print("Before cut-and-paste: " + CIPHER.decrypt(CIPHERUSER).decode('ascii'))

CIPHERUSER = CIPHERUSER.replace(CIPHERUSER[len(CIPHERUSER)-16:],
        CIPHERADMIN[len(CIPHERADMIN)-16:])

print("After  cut-and-paste: " + CIPHER.decrypt(CIPHERUSER).decode('ascii'))
