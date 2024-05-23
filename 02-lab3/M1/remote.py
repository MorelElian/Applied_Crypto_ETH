#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad

tn = telnetlib.Telnet("aclabs.ethz.ch", 50301)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


request = {"command": "howto"}
json_send(request)

response = json_recv()

print(response)
intro = response["res"].split(":")[-1][1:]
request = {"command": "encrypted_command", "encrypted_command": intro}

json_send(request)
response = json_recv()

ctr_enc = (
    int.from_bytes(bytes.fromhex(intro))
    .__xor__(1337)
    .__xor__(int.from_bytes(pad((b"intro"), 16)))
)
encrypted_flag = (
    int.from_bytes(pad(b"flag", 16))
    .__xor__(1337)
    .__xor__(ctr_enc)
    .to_bytes(16, byteorder="big")
    .hex()
)

print(response)
request = {"command": "encrypted_command", "encrypted_command": encrypted_flag}
json_send(request)
response = json_recv()

print(response)
