#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import secrets
from passlib.hash import argon2
import itertools
from Crypto.Hash import MD5, HMAC, SHA256, SHA1
import subprocess
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from string import ascii_letters, digits
from itertools import product
import numpy as np
import math
import decimal
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

ALPHABET = ascii_letters + digits

tn = telnetlib.Telnet("aclabs.ethz.ch", 50804)
# tn = telnetlib.Telnet("localhost", 50804)
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


def newton_method(y, max_iters=30000, tolerance=30):
    x = pow(2, 125)
    for _ in range(max_iters):
        x_prev = x
        x = (2 * x + y // (pow(x, 2))) // 3
        if abs(x - x_prev) < tolerance:
            print("OOOO", _)
            break
    print("end of iter", x - x_prev)
    return x


phonebook = {
    "Matteo": {
        "e": 0x3,
        "N": 0xE330A555ACE82210C484D89E8F75161D469662AB2957BECC52135108797CFB6B0300F1DA3BFF1354ECD289C13D720AFC958A1D6FF025A016EB12D6806CB2509EA6B8B9CCC51A17C6189718EEA10E90BB5BC28611841F3A4E54AC6AB1B107F621A58218DFC7F6C4F7D66E668D484034D1224868F583CD9A48C96ECBAA7E5104C3E9116F35148E9D995E377238EAA62AA96BA50905FAF1827991E10C41A11FCC78A943CCFEF733134274F75FE83ED30285A41E9E2411987515D058E1E056237235A3603AF8AB4C74D4202F84130105561BE2DF9D1498B2B85D35C12E2EE9FC5621DED5FFFDE701B8D0AD0A520C4838023D451BDF7FD70AC9C39647C771E545120F,
    },
    "Giacomo": {
        "e": 0x3,
        "N": 0xE44A141F75B959508C017C62FCF64EE49FBBC003CBF244264FBE35D905D9E5201AD6B5E1ECB4FB3446AA94EB8B0B7E4F8E609BB58161ECE8204D3D2366E4956748AD3E145CB0C82B38C7AD5EBE9E4035D74CBD1992EA9A2F7431730742CBE9381335AFBD9D2ED411839E332C3FCFD1ADDEAAF7DEDC448944ABE94FB3F5DD3A1AAB4EDB111DBE2FF091DA06D371514FFAD6219606DE85FD9F7BBDACA0E645A2005A59B7DF8B8DD84EB2904DF0265A69A5A081738469A3E5E19AB731EC44F57FF54597148E4DF6C0D6F64B433D0B36C8899914BD7B282EA5F70FB5921BA5724CDED01A43C309729EA77A9498B60F5A12A111E6C126EF244290D1F2291F23F211BF,
    },
    "Kenny": {
        "e": 0x3,
        "N": 0x98988BEA4F5B50B5C92B55114506C251209001E1E648C4E66D072FBA4B95A591B4336DC8D23F3BED89C79D2E77E567EBD739AEAE6E3693550AC1D89CAA07BB2CD82DE228243520F6239991746A84C67D083036190FA88746C4C0C32A81F179CFE3F89FA70C849C5EB9DF3F3353409B063B6F5213554D98831436F9455551D3E1E5A474F41415736BF08FB00628EE9F014FA25301404B7F7BA4C68DFDCF90F9A8BCA9D656EB8E52A41A0EE26F5222EE2194619126ED2B89D3F565481CDEB952D65561134ADB35C61E6A2D7694B40843DD84C797F96B83FD80833BA63388958E1A068AABBAD9EABA20180FD79E2A993A0618E4646AF5E357055806740E6308411D,
    },
}
encrypted_msg = {}
keys = {}
secrets_prof = {}
for prof in ["Matteo", "Giacomo", "Kenny"]:
    json_send({"command": "invite", "invitee": prof})
    res = json_recv()
    secrets_prof[prof] = int(res["ciphertext"], 16)
    keys[prof] = phonebook[prof]["N"]


## CRT part
print("GOING FOR CRT")
N = 1
secret = 0
used_keys = 0
for prof in keys:  # Computing prod N for CRT
    if keys[prof] > 0 and used_keys < 17:
        used_keys += 1
        N *= keys[prof]
print("GOT N NOW, moving forward")
used_keys = 0
for prof in keys:  # Using wikipedia notation
    if keys[prof] > 0 and used_keys < 17:
        used_keys += 1
        a = secrets_prof[prof]
        n_i = N // keys[prof]
        v_i = inverse(n_i, keys[prof])
        secret += a * n_i * v_i
print("GOT SECRET^17, moving forward")
secret = newton_method(secret % N)
print(secret)
secret_decoded = int.to_bytes(secret, 1000).decode()
print(secret_decoded)
