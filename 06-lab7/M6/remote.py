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


tn = telnetlib.Telnet("aclabs.ethz.ch", 50707)
# tn = telnetlib.Telnet("localhost", 50604)
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
recovered_key = b""

json_send({"command": "get_token"})
token = json_recv()["guest token"]
print(token)

flag = False
while not flag:
    json_send(
        {"command": "rekey", "key": (b"\x00" * 24 + secrets.token_bytes(32)).hex()}
    )
    res = json_recv()
    json_send({"command": "authenticate", "token": token})
    res = json_recv()
    print(res)
    if "resp" in res:
        print("we found it")
        flag = True

json_send({"command": "show_state", "prefix": "64"})
print("sent")
print(json_recv())
