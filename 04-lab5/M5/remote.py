#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
from Crypto.Hash import MD5, HMAC, SHA256, SHA1

tn = telnetlib.Telnet("aclabs.ethz.ch", 50505)
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


def md5_padding(message):
    # Longueur du message en bits
    message_len_bits = len(message) * 8

    # Ajouter un bit '1' au message
    message += b"\x80"

    # Nombre de zéros à ajouter pour atteindre une longueur de message mod 512 = 448
    padding_len = (56 - len(message) % 64) % 64

    # Ajouter des zéros
    message += b"\x00" * padding_len

    # Ajouter la longueur originale du message en bits, représentée en little-endian
    message += message_len_bits.to_bytes(8, byteorder="little")

    return message


c1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
c2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)
m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
recipe = b"Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]"
token = b"username:admin&m1:" + m1 + b"&fav_food_recipe:" + recipe
token_bis = b"username:admin&m1:" + c1 + b"&fav_food_recipe:"

h1 = MD5.new(c1).hexdigest()
h2 = MD5.new(c2).hexdigest()
print(h1, h2)

json_send({"command": "token"})
res = json_recv()
token_enc = res["token_enc"]
nonce = res["nonce"]
to_send = xor(xor(bytes.fromhex(token_enc), token), token_bis)

h1 = MD5.new(c1).hexdigest()
h2 = MD5.new(m1 + c2).hexdigest()
print(h1, h2)
json_send(
    {
        "command": "login",
        "token_enc": to_send.hex(),
        "nonce": nonce,
        "m2": (c2).hex(),
    }
)
print(json_recv())

json_send({"command": "flag"})
print(json_recv())
