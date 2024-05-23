#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
import subprocess
from shazam import SHAzam

tn = telnetlib.Telnet("aclabs.ethz.ch", 50602)
# tn = telnetlib.Telnet("localhost", 50602)
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
json_send({"command": "get_token"})
print("Full sent")
res = json_recv()
print(res)
command_string = res["authenticated_command"]
mac = res["mac"]
print(command_string, mac)

print(mac)
h = SHAzam()
bytes_object = bytes.fromhex(mac)


hex_integers = []

for i in range(0, len(bytes_object), 4):
    hex_int = int.from_bytes(bytes_object[i : i + 4], byteorder="big")
    hex_integers.append(hex_int)
h.hash = hex_integers
print(h.hash)
orig_msg = b"command=hello&arg=world"
added = (
    b"\x80"
    + b"\x00" * (63 - 8 - len(orig_msg) - 16)
    + b"\x00" * 6
    + int.to_bytes((len(orig_msg) + 16) * 8, length=2)
)
# h.update(added)
h.length = len(orig_msg + added) + 16
h.update(b"&command=flag")
new_mac = h.digest().hex()
print("FINAL SHA", new_mac)
new_command_string = (orig_msg + added + b"&command=flag").hex()
print(new_command_string)
json_send(
    {
        "command": "authenticated_command",
        "authenticated_command": new_command_string,
        "mac": new_mac,
    }
)
print(json_recv())
