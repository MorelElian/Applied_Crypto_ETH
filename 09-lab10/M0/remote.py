####M0 HOW TO GET THE FLAG
# We notice that we can repeat the nonce if we choose the right value for client_random
# by choosing client_random = q * (p-1) / 2, if x is even then h^x = 1 if x is odd then h^x = h thanks to fermat little theorem
# Then when we have noticed that we can find the secret key of the signing algorithm reversing the DSA signing process
##So we have only four differents random : h[:16] + 0*10, 0* 26, 0*16 + h[16:27], h[:16] + h[:11]
## Since we can ask for the flag only once, we msut be sure to recover the key, so we try to have the correct signature.

import telnetlib
import json
import secrets
import Crypto.Util
import Crypto
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
import subprocess
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from string import ascii_letters, digits
from itertools import product
from Crypto.Util.number import inverse
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey.DSA import DsaKey
from Crypto.Signature import DSS

ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 51000)
# tn = telnetlib.Telnet("localhost", 51000)

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


json_send({"command": "get_params"})
res = json_recv()
p, q, g = res["p"], res["q"], res["g"]
json_send({"command": "get_rand_params"})
res = json_recv()
rand_p, rand_q, rand_g = int(res["p"]), int(res["q"]), int(res["g"])
e = (rand_p - 1) // rand_q
random = inverse(e, rand_p) * ((rand_p - 1) // 2)

json_send({"command": "contribute_randomness", "random": random})
print(json_recv())
json_send({"command": "get_rand_params"})
res = json_recv()
print(res)
h = int.from_bytes(int.to_bytes(res["h"], 200))
print("HEX H", hex(h)[2:56])
h = hex(h)[2:56]  # get rid of 0x
possible_h = [
    int(h[:32] + h[:22], 16),
    int("0" * 32 + h[:22], 16),
    int(h[:32] + "0" * 22, 16),
    int(h[:2] + h[:32] + h[:22], 16),
    int(h[:2] + "0" * 32 + h[:22], 16),
    int(h[:2] + h[:32] + "0" * 22, 16),
]
flag = False

for i in range(10):
    json_send({"command": "sign", "message": "a1"})
    res = json_recv()
    print(res)

    if "signature" in res:
        signature = bytes.fromhex(res["signature"])
        r, s = int.from_bytes(signature[:28], "big"), int.from_bytes(
            signature[28:], "big"
        )
        print("R", r, "G", g, "P", p, "Q", q)
        hash_msg = SHA256.new(bytes.fromhex("a1"))
        int_hash = int.from_bytes(hash_msg.digest()[:28])
        print(int_hash)
        # guessing the key

        for h in possible_h:
            r_test = pow(g, h + 1, p) % q
            print("h test", h + 1, int.to_bytes(h + 1, 28).hex())
            print(r_test, r)
            if r_test == r:
                print("WE FIND X")
                x = ((((s * (h + 1) % q) - int_hash) % q) * inverse(r, q)) % q

                y = pow(g, x, p)
                key_dict = {
                    "y": Integer(y),
                    "g": Integer(g),
                    "p": Integer(p),
                    "q": Integer(q),
                    "x": Integer(x),
                }
                signing_key = DsaKey(key_dict)
                hash_mellon = SHA256.new(b"Mellon!")
                signer = DSS.new(signing_key, "fips-186-3")
                json_send(
                    {"command": "flag", "signature": signer.sign(hash_mellon).hex()}
                )
                res = json_recv()
                print(res)
                if "flag" in res:
                    print(res["flag"])
                    flag = True
                break

        else:
            print("ON ARRIVE PAS A RECUP X")

        if flag:
            break

        # Verify that we are correct :

        # try to get flag


DSS.new
