#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad
from string import ascii_letters

tn = telnetlib.Telnet("aclabs.ethz.ch", 50400)
# tn = telnetlib.Telnet("localhost", 50400)


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


msg_base = (b"\x00" * 7).hex() + "0"
print(msg_base, len(msg_base))
request = {"command": "encrypt", "msg": msg_base}
json_send(request)
cipher = json_recv()["result"]

print(cipher)
json_send({"command": "encrypt_secret"})
secret = json_recv()["result"]
print(secret)

request = {"command": "encrypt", "msg": msg_base}
json_send(request)
cipher_post = json_recv()["result"]

msg_xored = b"000000000000000"

flag_1 = xor(xor(bytes.fromhex(cipher), bytes.fromhex(secret[:32])), msg_xored)
flag_2 = xor(xor(bytes.fromhex(cipher_post), bytes.fromhex(secret[32:])), msg_xored)

flag_1 = flag_1[8:]

flag_2 = flag_2[:-6]

for letter in ascii_letters:
    json_send({"command": "flag", "solve": flag_1.decode() + letter + flag_2.decode()})
    res = json_recv()

    if "flag" in res:
        print("found", res)
        break
