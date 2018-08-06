string = "foo=bar&baz=qux&zap=zazzle"

def KVparse(string):
    kv = {}
    string = string.split('&')
    for s in string:
        s = s.split('=')
        kv[s[0]] = s[1]
    return kv

def profile_for(email):
    return "email="+email+"&uid=10&role=user"


KV = KVparse(profile_for("batsaras@csd.uoc.gr"))

print(KV)
