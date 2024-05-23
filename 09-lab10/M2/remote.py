####M0 HOW TO GET THE FLAG
## The problem is to be able to recreate signatures that verifies.
## We will construct new g2,y2,x2 so that r_v = r mod n and then the signature verifies.
## We want g2^s * y2^e = g^s * y^e
## Posing g2 = g^a*y^b and y2 =g2^c (c will be our private key)
## WE have a system of equation mod q-1, with 3 unknown values, we can fix one and resolve (we will try different value for the first one, so that figerprint works)


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
from Crypto.PublicKey import DSA
from secrets import randbelow, token_bytes


ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 51002)
# tn = telnetlib.Telnet("localhost", 51002)

block_size = 16
key_size = 16


class SchnorrSignatureScheme:
    def __init__(self, key: DSA.DsaKey):
        self._key = key
        assert self._key.q.bit_length() % 8 == 0
        assert self._key.p.bit_length() % 8 == 0
        self._q_bytes = self._key.q.bit_length() // 8
        self._p_bytes = self._key.p.bit_length() // 8

    def sign(self, msg: bytes) -> bytes:
        print("0")
        p, q, g, x = self._key.p, self._key.q, self._key.g, self._key.x
        p_bytes, q_bytes = self._p_bytes, self._q_bytes
        print("a")
        k = randbelow(q) + 1
        r = pow(g, k, p)
        print("b")
        data = r.to_bytes(p_bytes, "big") + msg

        e_b = SHA256.new(data=data).digest()[:q_bytes]
        print("c")
        e = int.from_bytes(e_b, "big")
        s = (k - x * e) % q
        print("d")
        return s.to_bytes(q_bytes, "big") + e_b

    def verify(self, msg, signature):
        p, g, y = self._key.p, self._key.g, self._key.y
        p_bytes, q_bytes = self._p_bytes, self._q_bytes

        s_b, e_b = signature[:q_bytes], signature[q_bytes:]
        s, e = int.from_bytes(s_b, "big"), int.from_bytes(e_b, "big")

        r_v = pow(g, s, p) * pow(y, e, p) % p
        data = r_v.to_bytes(p_bytes, "big") + msg
        e_b_v = SHA256.new(data=data).digest()[:q_bytes]

        if e_b_v != e_b:
            raise ValueError("Signature verification failed")

    @classmethod
    def new(cls, key: DSA.DsaKey):
        return SchnorrSignatureScheme(key)


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


len_f = 2
s = None
flag = False
while not flag:
    json_send({"command": "new_planet"})
    res = json_recv()
    planet_name = res["planet"]

    s, e_original = int(res["signature"][:40], 16), int(res["signature"][40:], 16)

    # fingerprint = bytes.fromhex(res["fingerprint"])
    key = bytes.fromhex(res["key"])
    fingerprint_original = SHA256.new(data=key).digest()[:len_f]
    key = DSA.import_key(key)
    p, q, y, g = key.p, key.q, key.y, key.g

    for a in range(1, 50000, 1):  # a of g^a
        try:
            c = ((s * inverse(a, p - 1) - s) % (p - 1) * inverse(e_original, p - 1)) % (
                p - 1
            )
            # print("at least c")
            b = (e_original * inverse((s + c * e_original), p - 1)) % (p - 1)
            # sigining with new key
            # print("got inverse")
            g2 = (pow(g, a, p) * pow(y, b, p)) % p
            new_key = DSA.construct(
                (pow(g2, c, p), g2, p, q, c),
                consistency_check=False,
            )
            # print("new_key")
            signer = SchnorrSignatureScheme.new(new_key)
            # print("signer")
            key_serialized = new_key.public_key().export_key()
            fingerprint = SHA256.new(data=key_serialized).digest()[:len_f]
            if fingerprint == fingerprint_original:
                print("GO FOR IT")
                # fingerprint = b"a"
                print("key_serialized")
                status = "this planet is good"
                signature = signer.sign(status.encode() + fingerprint)
                print(signature)
                dict_to_send = {
                    "command": "signal_planet",
                    "planet": planet_name,
                    "signature": signature.hex(),
                    "key": key_serialized.hex(),
                }
                print(dict_to_send)
                json_send(dict_to_send)
                res = json_recv()
                print(res)
                if "flag" in res:
                    print(res["flag"])
                    flag = True
                    break
        except Exception as e:
            pass
            # print(e)
