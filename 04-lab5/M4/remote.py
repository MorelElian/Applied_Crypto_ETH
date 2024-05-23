#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1

tn = telnetlib.Telnet("aclabs.ethz.ch", 50504)
# tn = telnetlib.Telnet("localhost", 50404)
block_size = 16


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


json_send({"command": "salt"})
salt = bytes.fromhex(json_recv()["salt"])
print("SALT:", salt)
pw = bytes(secrets.choice(range(ord("a"), ord("z"))) for _ in range(5))
passwords = itertools.product("abcdefghijklmnopqrstuvwxyz", repeat=5)
hash_dict = {}
compteur = 0
for password in passwords:

    password = "".join(password)
    compteur += 1
    if compteur % 100000 == 0:
        print(compteur)
    hsh = HMAC.new(salt, msg=password.encode(), digestmod=SHA256).hexdigest()
    hash_dict[hsh] = password

for i in range(5):
    json_send({"command": "password"})
    hsh = json_recv()["pw_hash"]
    json_send({"command": "guess", "password": hash_dict[hsh]})
    print(json_recv())
json_send({"command": "flag"})
print(json_recv())
