#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from string import ascii_letters, digits

additional_characters = "{}[]()!@#$%^&*_+-=,.<>?;:'\"\\|~`"
ALPHABET = ascii_letters + digits + additional_characters
tn = telnetlib.Telnet("aclabs.ethz.ch", 50302)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


print(b"flag".hex())
do_not_care = b"aaaaaaaaaaaaaaa"
to_keep = ""
for i in range(256):
    right_nb = 0
    msg = (do_not_care).hex() + hex(i)[2:]

    request = {"command": "encrypted_command", "encrypted_command": msg}
    json_send(request)
    response = json_recv()
    if response["res"][0] == "N":
        to_keep = hex(i)[2:]
        print(response)

request = {
    "command": "encrypted_command",
    "encrypted_command": b"bbbbbbbbbbbbbbb".hex() + to_keep,
}
json_send(request)
print(json_recv())
print(to_keep)
to_get = "666c61670c0c0c0c0c0c0c0c0c0c0c"
for i in range(15):
    print("i :", i)
    print(to_keep)
    for j in range(256):

        trying = hex(j)[2:]
        trying = "0" + trying if len(trying) == 1 else trying

        msg = (b"a" * (14 - i)).hex() + trying + to_keep

        request = {"command": "encrypted_command", "encrypted_command": msg}
        json_send(request)
        response = json_recv()
        # print(response)

        if (
            response["res"][-2 * (i + 1) : len(response["res"]) - 2 * (i + 1) + 2]
        ) == to_get[-2 * (i + 1) : len(to_get) - 2 * (i + 1) + 2]:
            print(to_get, response)
            # a = input()
            to_keep = hex(j)[2:] + to_keep
            break

for j in range(256):
    request = {
        "command": "encrypted_command",
        "encrypted_command": to_keep[:-2] + hex(j)[2:],
    }
    json_send(request)
    response = json_recv()
    print(response)
print(to_keep)
