#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50303)


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
to_send = response["res"].split(":")[-1][1:]
iv = to_send[0:32]
ciphertext = to_send[32:64]
print(to_send)
intro = "696e74726f0b0b0b0b0b0b0b0b0b0b0b"
flag = "666c61670c0c0c0c0c0c0c0c0c0c0c0c"

new_iv_1 = int(iv, 16).__xor__(int(intro, 16)).__xor__(int(flag, 16)).to_bytes(16).hex()
print("iv", iv)
print("new_iv", new_iv_1)

request = {"command": "encrypted_command", "encrypted_command": new_iv_1 + ciphertext}
json_send(request)
response = json_recv()
print(response)
request = {"command": "howto"}
json_send(request)

response = json_recv()
request = {"command": "encrypted_command", "encrypted_command": new_iv_1 + ciphertext}
json_send(request)
response = json_recv()
