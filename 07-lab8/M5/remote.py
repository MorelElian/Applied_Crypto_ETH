#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
import subprocess
from Crypto.Hash import HMAC, SHA256
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


ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50805)
# tn = telnetlib.Telnet("localhost", 50803)
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


def newton(x, value, i):
    # func is x³ - value

    f_x = pow(x, 3) - value
    # print(f_x)
    if abs(f_x) <= 2 or i > 50:
        return x
    fp = 3 * pow(x, 2)
    f_x = pow(x, 3) - value
    new_x = 2 * x / 3 + value / (3 * pow(x, 2))
    return newton(new_x, value, i + 1)


inverse_1 = inverse(23, 31)
inverse_2 = inverse(31, 23)

json_send({"command": "pub_key"})
N = int(json_recv()["N"], 16)
json_send({"command": "encrypt", "e": 23})
res = json_recv()
print(res)
c1 = int(res["ciphertext"], 16)
json_send({"command": "encrypt", "e": 31})
res = json_recv()
print(res)
c2 = int(res["ciphertext"], 16)
print(c1, c2, sep="\n")
m = (pow(c1, inverse_1, N) * pow(c2, inverse_2, N)) % N
print(int.to_bytes(m, 164))
message = int.from_bytes(
    "flag{test_flag_very_long_flag_like_really_really_long_so_long}".encode()
)
gcd, i1, i2 = extended_gcd(23, 31)
mul = (pow(c1, i1, N) * pow(c2, i2, N)) % N
print(i1 * 23 + i2 * 31)
print(int.to_bytes(mul, 150))
