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
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50803)
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
N, e = int(res["N"]), res["e"]
print("N e", N, e)

decimal.getcontext().prec = 1000
n_dec = decimal.Decimal(N)
rac = int(n_dec.sqrt())
print("\n\n\n", rac)
if pow(rac, 2) > n_dec:
    diff = pow(rac, 2) - n_dec
    print("FOUND DIFF", diff, math.sqrt(diff))
if int(math.sqrt(diff)) == math.sqrt(diff):
    p = rac - int(math.sqrt(diff))
    q = rac + int(math.sqrt(diff))
    e = 65537

    N = p * q
    phiN = (p - 1) * (q - 1)
    d = number.inverse(e, phiN)

    key = RSA.construct((N, e, d))
    cipher = PKCS1_OAEP.new(key)
    a = cipher.decrypt(bytes.fromhex(flag_encrypted))
    print(a)
