#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
import subprocess


tn = telnetlib.Telnet("aclabs.ethz.ch", 50600)
# tn = telnetlib.Telnet("localhost", 50600)
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
json_send({"command": "token"})
print("Full sent")
res = json_recv()["token"]
command_string = res["command_string"]
mac = res["mac"]
print(command_string, mac)
# Arguments pour la commande hashpump

# Appeler hashpump avec les arguments
print("process started")
process = subprocess.Popen(
    ["hashpump"]
    + [
        "-d",
        bytes.fromhex(command_string).decode(),
        "-k",
        "16",
        "-s",
        mac,
        "-a",
        "&command=flag",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

# Récupérer la sortie
output, error = process.communicate()
new_command_string = output.decode().split("\n")[-2]
new_mac = output.decode().split("\n")[1].split(" ")[-1]
print(output.decode())
new_command_string = (
    b"command=hello&arg=world" + b"\x80" + b"\x00" * 22 + b"\x018&command=flag"
).hex()
print(new_command_string)
json_send(
    {
        "command": "token_command",
        "token": {"command_string": new_command_string, "mac": new_mac},
    }
)
print(json_recv())
