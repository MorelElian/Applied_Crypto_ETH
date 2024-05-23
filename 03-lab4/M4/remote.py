#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets

tn = telnetlib.Telnet("aclabs.ethz.ch", 50404)
# tn = telnetlib.Telnet("localhost", 50404)
block_size = 16


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


for k in range(50):
    try:
        json_send({"command": "list", "user": "admin"})
        res = json_recv()
        file_id = res["result"][0]
        print(file_id)

        iv = secrets.token_bytes(16).hex()
        random_msg = secrets.token_bytes(16).hex()
        json_send({"command": "get", "ctxt": iv + random_msg, "user": "admin"})
        res = json_recv()
        print(res)
        encrypted_file_id = ""
        needed_for_padding = []
        for i in range(1, 17, 1):
            for j in range(256):
                trying = hex(j)[2:]
                trying = "0" + trying if len(trying) == 1 else trying
                suffix_iv = iv[2 * i :]

                needed = ""
                for found in needed_for_padding:

                    needed += "0" + found[2:] if len(found[2:]) == 1 else found[2:]
                trying_iv = needed + trying + suffix_iv

                # print(trying_iv)
                json_send(
                    {"command": "get", "ctxt": trying_iv + random_msg, "user": "admin"}
                )
                res = json_recv()
                # print(res)
                if res["error"] == "File not found!":
                    if j == 0:
                        print(trying, trying_iv, res)
                    needed_for_padding.append(
                        hex(int(trying, 16).__xor__(1))
                    )  # Gives 0
                    print("FIND ONE CARAC :", j)

        hex_string = "".join(
            (
                "0" + hex(int(x, 16))[2:]
                if len(hex(int(x, 16))[2:]) == 1
                else hex(int(x, 16))[2:]
            )
            for x in needed_for_padding
        )
        file_id = "01" + file_id
        print(hex_string)
        print(needed_for_padding)
        json_send(
            {
                "command": "get",
                "ctxt": xor(bytes.fromhex(file_id), bytes.fromhex(hex_string)).hex()
                + random_msg,
                "user": "admin",
            }
        )

        res = json_recv()["result"]
        json_send({"command": "flag", "solve": res})
        print(json_recv())
    except:
        continue
