#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad
from string import ascii_letters
import random

tn = telnetlib.Telnet("aclabs.ethz.ch", 50402)
# tn = telnetlib.Telnet("localhost", 50402)


def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))


MESSAGES = [
    "Pad to the left",
    "Unpad it back now y'all",
    "Game hop this time",
    "Real world, let's stomp!",
    "Random world, let's stomp!",
    "AES real smooth~",
]
MESSAGES_P = [msg.ljust(32) for msg in MESSAGES]
dict_seed = {}
for i in range(6):
    random.seed(MESSAGES_P[i])
    iv = random.randbytes(16).hex()
    dict_seed[iv] = MESSAGES_P[i]
print(dict_seed)
MESSAGES_FIRST_BLOCK = [
    "Pad to the left ",
    "Unpad it back no",
    "Game hop this ti",
    "Real world, let'",
    "Random world, le",
    "AES real smooth~",
]


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
res = json_recv()
first_iv = res["iv"]
origin = res["ctxt"]
print(origin)
seed = dict_seed[first_iv]
random.seed(seed)
iv = random.randbytes(16)
first_iv = bytes.fromhex(first_iv)
for j in range(64):
    if j:
        first_iv = random.randbytes(16)
        json_send({"command": "encrypt", "msg": ""})
        res = json_recv()
        origin = res["ctxt"]
    for i in range(6):
        iv = random.randbytes(16)
        print("IV PLANNED", iv.hex(), type(iv))

        msg = xor(xor(iv, first_iv), MESSAGES_FIRST_BLOCK[i].encode())
        json_send({"command": "encrypt", "msg": msg.hex()})
        res = json_recv()
        print("iv", res["iv"])
        print("ctxt", res["ctxt"])
        if res["ctxt"][:10] == origin[:10]:
            print("FOUND msg is :", MESSAGES_P[i])
            json_send({"command": "guess", "guess": MESSAGES_P[i]})
            print(json_recv())
            break
json_send({"command": "flag"})
print(json_recv())
