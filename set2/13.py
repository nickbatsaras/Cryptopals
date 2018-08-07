from Crypto.Cipher import AES
from cryptopals    import PKCS7
from os            import urandom

def KVparse(string):
    kv = "{\n"
    string = string.split('&')
    for s in string:
        s = s.split('=')
        kv += "\t" + s[0] + ": " + s[1] + "\n"
    kv += "}"
    return kv

def profile_for(email):
    return "email="+email+"&uid=10&role=user"


KEY = urandom(16)
CIPHER = AES.new(KEY, AES.MODE_ECB)

EMAIL = "foo@bar.com"

PLAINUSER  = profile_for(EMAIL)
PLAINUSER  = PKCS7(PLAINUSER)
CIPHERUSER = CIPHER.encrypt(PLAINUSER)

PLAINADMIN  = profile_for(EMAIL).replace("user", "admin")
PLAINADMIN  = PKCS7(PLAINADMIN)
CIPHERADMIN = CIPHER.encrypt(PLAINADMIN)

PLAINUSER = CIPHER.decrypt(CIPHERUSER).decode('ascii')
print("Before cut-and-paste: " + PLAINUSER)
print(KVparse(PLAINUSER))

for i in range(len(CIPHERUSER)):
    if CIPHERUSER[i] != CIPHERADMIN[i]:
        break

CIPHERUSER = CIPHERUSER.replace(CIPHERUSER[i:], CIPHERADMIN[i:])

PLAINUSER = CIPHER.decrypt(CIPHERUSER).decode('ascii')
print("After cut-and-paste: " + PLAINUSER)
print(KVparse(PLAINUSER))
