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

tn = telnetlib.Telnet("aclabs.ethz.ch", 50801)
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


json_send({"command": "encrypted_flag"})
res = json_recv()
flag_encrypted = res["encrypted_flag"].split(" ")[-1]
N, e = res["N"], res["e"]
print("N", N, "e", e)
flag_encrypted = int(flag_encrypted, 16)
ctxt_bis = hex((pow(2, int(e, 16)) * flag_encrypted) % int(N, 16))[2:]
print("CTXT BIS ", ctxt_bis)
json_send(
    {
        "command": "decrypt",
        "ciphertext": hex((pow(2, int(e, 16)) * flag_encrypted) % int(N, 16))[2:],
    }
)
res = json_recv()
print(res)
test = int(res["res"], 16) // 2
print(int.to_bytes(test, 150))
