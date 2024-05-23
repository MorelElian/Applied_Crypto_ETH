#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50342)
# tn = telnetlib.Telnet("localhost", 50342)
block_size = 16


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


for i in range(10):
    request = {"command": "challenge"}
    json_send(request)
    challenge = json_recv()["res"]
    iv = challenge[:32]
    needed_for_padding = []
    for k in range(1, 17):
        iv_last = iv[-2 * k : len(iv) - 2 * (k - 1)]
        cipher = challenge[32:]
        padding = ""
        for l in range(len(needed_for_padding)):
            tmp = hex(needed_for_padding[l].__xor__(l + 1).__xor__(k))[2:]
            tmp = "0" + tmp if len(tmp) == 1 else tmp
            padding = tmp + padding
        print(padding)
        for j in range(256):

            trying = hex(j)[2:]
            trying = "0" + trying if len(trying) == 1 else trying

            request = {
                "command": "decrypt",
                "ciphertext": iv[: len(iv) + (-2 * k)] + trying + padding + cipher,
            }

            json_send(request)
            res = json_recv()["res"]
            # print("len_res", len(res))
            if not len(res) == 128:

                print("Char FOUND k : ", k)
                print(j, hex(j))
                needed_for_padding.append(j)
                break
    reconstitued_chall = ""
    for l in range(len(needed_for_padding)):
        reconstitued_chall = (
            chr(
                needed_for_padding[l]
                .__xor__(l + 1)
                .__xor__(int(iv[len(iv) - 2 * (l + 1) : len(iv) - 2 * (l)], 16))
            )
            + reconstitued_chall
        )
    json_send({"command": "guess", "guess": reconstitued_chall})
    print(json_recv())

print(needed_for_padding)
json_send({"command": "flag"})
response = json_recv()
print(response)
