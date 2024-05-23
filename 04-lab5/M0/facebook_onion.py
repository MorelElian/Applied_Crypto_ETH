from Crypto.Hash import MD5, HMAC, SHA256, SHA1
from Crypto.Protocol.KDF import scrypt

PW = "6f6e696f6e732061726520736d656c6c79"
SECRET = "6275742061726520617765736f6d6520f09f988b"
SALT = "696e2061206e69636520736f6666726974746f21"


def onion(pw, salt):
    h1 = MD5.new(pw).digest()
    h2 = HMAC.new(key=salt, msg=h1, digestmod=SHA1).digest()
    h3 = HMAC.new(key=bytes.fromhex(SECRET), msg=h2, digestmod=SHA256).digest()
    h4 = scrypt(password=h3, salt=salt, N=2**10, r=32, p=2, key_len=64)
    h5 = HMAC.new(key=salt, msg=h4, digestmod=SHA256).digest()
    return h5.hex()


pw = bytes.fromhex(PW)
salt = bytes.fromhex(SALT)

result = onion(pw, salt)
print(result)
