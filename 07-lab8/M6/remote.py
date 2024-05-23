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
import time


ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50806)
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


E = 65537
while True:
    json_send({"command": "generate"})
    res = json_recv()
    N1, index1 = res["N"], res["key_index"]
    json_send({"command": "generate"})
    time.sleep(2)
    res = json_recv()
    N2, index2 = res["N"], res["key_index"]
    # print(GCD(N1, N2))
    if GCD(N1, N2) > 1:
        p = GCD(N1, N2)
        q = N1 // p
        N = p * q
        print(N)
        phiN = (p - 1) * (q - 1)
        d = inverse(E, phiN)
        json_send({"command": "encrypt", "index": index1})
        res = json_recv()
        print(res)
        cipher = PKCS1_OAEP.new(RSA.construct((N, E, d)))
        encrypted_flag = res["encrypted_flag"]
        resultat = cipher.decrypt(bytes.fromhex(encrypted_flag))
        print(resultat)
        break
