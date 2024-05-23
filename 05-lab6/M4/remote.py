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

ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50603)
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


print("not sent yet")
json_send({"command": "corrupt"})
print("Full sent")
auth_k = bytes.fromhex(json_recv()["res"].split(" ")[-1])
print(auth_k)

combinations = ["".join(comb) for comb in product(ALPHABET, repeat=4)]

dict_hash = {}

for i, combination in enumerate(combinations):
    if i % 10000 == 0:
        print(i)
    tag = HMAC.new(auth_k, combination.encode(), SHA256).digest()
    dict_hash[tag.hex()] = combination


for i in range(128):
    json_send({"command": "challenge"})
    chall_str = json_recv()["res"]
    tag_chall = chall_str[-len(tag.hex()) :]
    json_send({"command": "guess", "guess": dict_hash[tag_chall]})
    print(json_recv())
json_send({"command": "flag"})
print(json_recv())
