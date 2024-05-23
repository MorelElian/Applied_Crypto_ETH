#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets

tn = telnetlib.Telnet("aclabs.ethz.ch", 50405)
# tn = telnetlib.Telnet("localhost", 50405)
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


for a in range(4):
    try:
        json_send({"command": "list"})
        json_send({"command": "list"})
        res = json_recv()
        print(res)
        res = json_recv()
        print(res)
        hash = res["result"][0]
        suffix = hash
        ptxt = (
            b"\x00" * 10
            + b": don't forget that this is your secret AC login code."
            + b" " * 32
        )
        print(len(ptxt))

        for k in range(6):
            iv = secrets.token_bytes(16).hex()

            needed_for_padding = []
            compt0 = 0
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
                        {
                            "command": "backup",
                            "ctxt": trying_iv + suffix,
                            "user": "admin",
                        }
                    )
                    res = json_recv()

                    if "result" in res:
                        if j == 0:
                            print(trying, trying_iv, res)
                        print(res)
                        needed_for_padding.append(
                            hex(int(trying, 16).__xor__(1))
                        )  # Gives 0
                        final_hash = "0" + hex(i)[2:]
                        print("FIND ONE CARAC :", j)
                        if j == 0:
                            compt0 += 1
                        if compt0 > 4:
                            raise ValueError("On s'est merdé sur les 0")
            hex_string = "".join(
                (
                    "0" + hex(int(x, 16))[2:]
                    if len(hex(int(x, 16))[2:]) == 1
                    else hex(int(x, 16))[2:]
                )
                for x in needed_for_padding
            )
            if k < 5:
                ptxt_block = ptxt[len(ptxt) - 16 * (k + 1) : len(ptxt) - 16 * k]
                print(ptxt_block)
                reconstitued_ctxt = xor(ptxt_block, bytes.fromhex(hex_string)).hex()
                suffix = reconstitued_ctxt + suffix

                print("reconstitued_ctxt", suffix)
            else:
                ptxt_block = ""

        json_send({"command": "backup", "ctxt": hex_string + suffix})
        print(json_recv())

        for secret in range(0, 10000):
            secret = str(secret)
            ptxt_block = (
                b"\x00" * (9 - len(secret)) + b"\x01" + secret.encode() + b": don'"
            )
            # print("PTXT BLOCK", ptxt_block)
            reconstitued_ctxt = xor(ptxt_block, bytes.fromhex(hex_string)).hex()
            # print("RECONSTITUED CTXT", reconstitued_ctxt)
            full_chain = reconstitued_ctxt + suffix
            json_send(
                {"command": "check", "ctxt_hash": hash, "ctxt_start": reconstitued_ctxt}
            )
            res = json_recv()
            if res["result"]:
                print("FOUND NUMBER :", secret)
                break
        json_send(
            {
                "command": "flag",
                "solve": (
                    secret.encode()
                    + b": don'"
                    + b"t forget that this is your secret AC login code."
                    + b" " * 32
                ).hex(),
            }
        )
        print(json_recv())
    except:
        print("#####000####")
        continue
