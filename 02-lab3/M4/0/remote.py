#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets

tn = telnetlib.Telnet("aclabs.ethz.ch", 50340)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


request = {"command": "hex_command", "hex_command": "FFFFFFFFFFFF"}
json_send(request)

response = json_recv()

print(response)
for i in range(1):

    for j in range(306):
        iv = secrets.token_hex(16)
        ciphertext = secrets.token_hex(16)

        request = {"command": "decrypt", "ciphertext": iv + ciphertext}
        json_send(request)
        response = json_recv()
        if len(response["res"]) == 128:
            json_send({"command": "guess", "guess": True})
            print(json_recv())
        else:
            print("Failli se faire avoir")
json_send({"command": "flag"})
print((json_recv()))
