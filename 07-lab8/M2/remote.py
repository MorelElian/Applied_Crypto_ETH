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

x = 125
cube_root = np.cbrt(x)
print(cube_root)

ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50802)
# tn = telnetlib.Telnet("localhost", 50801)
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


json_send({"command": "encrypted_flag"})
res = json_recv()


flag_encrypted = res["ctxt"].split(" ")[-1]
print("FLAG ENCRYPTED", flag_encrypted)
result = (
    3036112636985936945680423109451757908418398271763956003087747227546837426373096317
)
print("FLAG", int.to_bytes(result, 50))
flag_encrypted = int(flag_encrypted)
root = newton(10000000000000000, flag_encrypted, 1)
print("ROOT", root, pow(root, 3))
