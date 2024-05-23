import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1


passwords = itertools.product("abcdefghijklmnopqrstuvwxyz", repeat=6)
print(passwords)
SALT = bytes.fromhex("b49d3002f2a089b371c3")
HASH = bytes.fromhex("d262db83f67a37ff672cf5e1d0dfabc696e805bc")
compteur = 10000

for password in passwords:
    password = "".join(password)
    compteur += 1
    if compteur % 100000 == 0:
        print(compteur)
    trying = HMAC.new(msg=SALT, key=password.encode(), digestmod=SHA1).digest()
    if HASH == trying:
        print(password)
