#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2

tn = telnetlib.Telnet("aclabs.ethz.ch", 50501)
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


json_send({"command": "password"})
pw = json_recv()["res"]
json_send({"command": "guess", "guess": argon2.hash(bytes.fromhex(pw))})
print(json_recv())
