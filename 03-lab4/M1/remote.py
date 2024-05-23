#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad
from string import ascii_letters

# tn = telnetlib.Telnet("aclabs.ethz.ch", 50401)
tn = telnetlib.Telnet("localhost", 50401)


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


json_send({"command": "encrypt", "msg": ""})
print(json_recv())
guessed = ""
for i in range(1, 17):
    prefix = "00" * (16 - i)  # len 14

    for letter in ascii_letters:

        msg = "00" * 16 + prefix + guessed + letter.encode().hex() + prefix

        json_send({"command": "encrypt", "msg": msg})
        res = json_recv()["result"]

        if res[32:64] == res[96:128]:

            guessed += letter.encode().hex()
            break
json_send({"command": "flag", "solve": bytes.fromhex(guessed).decode()})
print(json_recv())
