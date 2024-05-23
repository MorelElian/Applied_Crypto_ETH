p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
g = 35347793643784512578718068065261632028252678562130034899045619683131463682036436695569758375859127938206775417680940187580286209291486550218618469437205684892134361929336232961347809792699253935296478773945271149688582261042870357673264003202130096731026762451660209208886854748484875573768029653723060009335

print(pow(g, p - 1, p))

#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
import subprocess
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from string import ascii_letters, digits
from itertools import product
import numpy as np
import math
import decimal
from Crypto.Util.number import inverse, GCD
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import time


ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50900)
# tn = telnetlib.Telnet("localhost", 50806)
block_size = 16
key_size = 16


def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
g = 35347793643784512578718068065261632028252678562130034899045619683131463682036436695569758375859127938206775417680940187580286209291486550218618469437205684892134361929336232961347809792699253935296478773945271149688582261042870357673264003202130096731026762451660209208886854748484875573768029653723060009335

json_send({"command": "alice_initialisation"})
res = json_recv()
print(res)
json_send(
    {
        "command": "bob_initialisation",
        "alice_hello": {
            "resp": "Hi Bob, I'm Alice. This is my public key",
            "alice_key": 1,
        },
    }
)
res = json_recv()
print(res)
json_send(
    {
        "command": "alice_finished",
        "bob_hello": {
            "resp": "Hi Alice, I'm Bob. This is my public key",
            "bob_key": 1,
        },
    }
)
res = json_recv()
print(res)
nonce, encrypted_flag = res["nonce"], res["encrypted_flag"]
print(nonce)
alice_shared = pow(1, 1, p)
shared_bytes = alice_shared.to_bytes(alice_shared.bit_length(), "big")
secure_key = HKDF(
    master=shared_bytes,
    key_len=32,
    salt=b"Secure alice and bob protocol",
    hashmod=SHA512,
    num_keys=1,
)
cipher = AES.new(secure_key, AES.MODE_CTR, nonce=bytes.fromhex(nonce))
print(cipher.decrypt(bytes.fromhex(encrypted_flag)))
