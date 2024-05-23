#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50341)
# tn = telnetlib.Telnet("localhost", 50341)
block_size = 16


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


for i in range(100):
    request = {"command": "challenge"}
    json_send(request)
    challenge = json_recv()["res"]
    print(challenge)
    iv = challenge[:32]
    iv_last = iv[-2:]
    cipher = challenge[32:]
    for j in range(256):

        trying = hex(j)[2:]
        trying = "0" + trying if len(trying) == 1 else trying

        request = {"command": "decrypt", "ciphertext": iv[:-2] + trying + cipher}

        json_send(request)
        res = json_recv()["res"]
        # print("len_res", len(res))
        if not len(res) == 128:
            print("Char FOUND i : ", i)
            print(j, hex(j))
            print((hex(j.__xor__(1).__xor__(int(iv_last, 16)))))
            last_char = chr(j.__xor__(1).__xor__(int(iv_last, 16)))
            json_send({"command": "guess", "guess": last_char})
            print(json_recv())
            break

json_send({"command": "flag"})
response = json_recv()
print(response)
