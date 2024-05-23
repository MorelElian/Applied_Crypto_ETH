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

ascii_printable = [chr(i) for i in range(32, 127)]

# Ajouter les caractères spéciaux supplémentaires si nécessaire
special_characters = [
    "{",
    "}",
    "/",
    "&",
    "#",
    "@",
    "$",
    "%",
    "^",
    "*",
    "(",
    ")",
    "_",
    "+",
    "=",
    "-",
    ",",
    ".",
    ":",
    ";",
    "<",
    ">",
    "[",
    "]",
    "|",
    "\\",
    "`",
    "~",
    "'",
    '"',
]

# Combiner les deux listes
all_characters = ascii_printable + special_characters
ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50604)
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
json_send({"command": "flag"})
res = json_recv()
print(res)
nonce, ctxt_flag, mac_tag_flag = res["nonce"], res["ctxt"], res["mac_tag"]
test = res["ctxt"][0:4]
print(test, ctxt_flag)
json_send({"command": "encrypt", "ptxt": "fl"})
mac_tag = json_recv()["mac_tag"]
json_send({"command": "decrypt", "nonce": nonce, "ctxt": test, "mac_tag": mac_tag})

print(json_recv())
recovered = ""
for i in range(2, len(ctxt_flag) + 2, 2):
    for letter in all_characters:
        json_send({"command": "encrypt", "ptxt": recovered + letter})
        res = json_recv()
        mac_tag = res["mac_tag"]
        json_send(
            {
                "command": "decrypt",
                "nonce": nonce,
                "ctxt": ctxt_flag[0:i],
                "mac_tag": mac_tag,
            }
        )
        if json_recv()["success"] == True:
            recovered += letter
            print(recovered)
