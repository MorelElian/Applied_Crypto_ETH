#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad
from string import ascii_letters
import random

tn = telnetlib.Telnet("aclabs.ethz.ch", 50403)
# tn = telnetlib.Telnet("localhost", 50403)


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
print("RES", res)
first_iv = res["iv"]
origin = res["ctxt"]
print(origin)
seed = dict_seed[first_iv]
random.seed(seed)
iv = random.randbytes(16)
first_iv = bytes.fromhex(first_iv)
found = ""
for i in range(1, 17):

    iv_oracle = random.randbytes(16)
    prefix_iv_oracle = iv_oracle[: len(iv_oracle) - i]
    if i == 1:
        last = hex(iv_oracle[-1])[2:]
        last = "0" + last if len(last) == 1 else last
    else:
        last = iv_oracle[len(iv_oracle) - i :].hex()
    msg = prefix_iv_oracle.hex()
    json_send({"command": "encrypt", "msg": msg})
    res = json_recv()
    iv_p = res["iv"]
    ctxt = res["ctxt"]
    origin = ctxt[:32]

    for letter in ascii_letters:
        iv = random.randbytes(16)

        trying = "0" * (32 - 2 * i) + found + letter.encode().hex()

        xored = "0" * (32 - 2 * i) + last
        # print(xored)
        # print(trying)
        json_send(
            {
                "command": "encrypt",
                "msg": xor(xor(iv, bytes.fromhex(trying)), bytes.fromhex(xored)).hex(),
            }
        )
        res = json_recv()

        if origin == res["ctxt"][:32]:
            print("FOUND LETTER", letter)
            found += letter.encode().hex()
            break

for i in range(1, 17):
    iv_oracle = random.randbytes(16)
    prefix_iv_oracle = iv_oracle[: len(iv_oracle) - i]
    if i == 1:
        last = hex(iv_oracle[-1])[2:]
        last = "0" + last if len(last) == 1 else last
    else:
        last = iv_oracle[len(iv_oracle) - i :].hex()
    json_send({"command": "encrypt", "msg": prefix_iv_oracle.hex()})

    res = json_recv()["ctxt"]
    cipher_1 = res[:32]
    second_block = res[32:64]
    last = bytes.fromhex("0" * (32 - 2 * i) + last)
    found_prefix = bytes.fromhex("0" * (32 - 2 * i) + (found[: 2 * i]))
    for letter in ascii_letters:

        iv = random.randbytes(16)

        first_block = xor(xor(iv, last), found_prefix).hex()
        trying = found[2 * i :] + letter.encode().hex()
        json_send({"command": "encrypt", "msg": first_block + trying})
        res = json_recv()["ctxt"]
        if res[32:64] == second_block:
            print("FOUND LETTER 2ND BLOCK", letter)
            found += letter.encode().hex()
            break
json_send({"command": "guess", "guess": bytes.fromhex(found).decode()})
print(json_recv())
