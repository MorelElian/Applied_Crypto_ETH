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
import rsa

ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50800)
# tn = telnetlib.Telnet("localhost", 50603)
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


pk, sk, primes = rsa.rsa_key_gen()
json_send(
    {
        "command": "set_parameters",
        "N": pk[0],
        "e": pk[1],
        "d": sk[1],
        "p": primes[0],
        "q": primes[1],
    }
)
print(json_recv())
json_send({"command": "encrypted_flag"})
flag_encrypted = int(json_recv()["res"].split(" ")[-1])
flag = rsa.rsa_dec(sk, flag_encrypted)
print("decrypted")
flag = int.to_bytes(flag, 1000)
print(flag)
