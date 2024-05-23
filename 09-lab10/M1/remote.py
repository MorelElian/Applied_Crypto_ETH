#### M1 HOW TO GET THE FLAG
### There is 18 vpeople who are voting, thanks to CRT we can compute secret^17 mod prod(N_i), but secret < N_i for all i
### So it is over the integer and not mod pro(N_i), with dichotomie, we can recover secret.
### We also need to recover public keys, we have several public messages and their encryption : So if we have m_1^e = c_1 mod n
### and m_2^e = c_2 mod n then n divides (m1^e-m2^e) - (c1^e - c2^e)
### Since if n divides a and b it divides  a +b we can find candidates by computing gcd(m1^e - m2^e, c1- c2)
### To be sure that we found the right n we will compute the encryption of the message we know and verify, if it's not the case we take another pair of message
### If we don't succeed, well, happens.
####

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
from Crypto.Util.number import inverse, GCD, bytes_to_long, long_to_bytes
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey.DSA import DsaKey
from Crypto.Signature import DSS

ALPHABET = ascii_letters + digits

# tn = telnetlib.Telnet("aclabs.ethz.ch", 51001)
for i in range(5):
    try:
        tn = telnetlib.Telnet("aclabs.ethz.ch", 51001)
        # tn = telnetlib.Telnet("localhost", 51001)

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
                x = (16 * x + y // (pow(x, 16))) // 17
                if abs(x - x_prev) < tolerance:
                    print("OOOO", _)
                    break
            print("end of iter", x - x_prev)
            return x

        MESSAGES = [
            "We shall vote to excommunicate the student.",
            "Store your vote with the secret in the last message...",
            "...and that's to prevent tampering.",
            "And the only way this student will ever have freedom or peace, now or ever...",
            "...is in the end of this graded lab.",
            "I have served.",
            "I will be of service.",
        ]
        e = 17

        def str_to_int(message):
            return int.from_bytes(message.encode())

        ## Fonction to find n
        def find_n(list_msg):
            for i in range(len(list_msg)):
                for j in range(i + 1, len(list_msg)):
                    for k in range(j + 1, len(list_msg)):
                        m_i_enc = pow(str_to_int(MESSAGES[i]), e)
                        c_i = list_msg[i]
                        m_j_enc = pow(str_to_int(MESSAGES[j]), e)
                        c_j = list_msg[j]
                        m_k_enc = pow(str_to_int(MESSAGES[k]), e)
                        c_k = list_msg[k]

                        candidate = GCD(
                            (m_i_enc - m_j_enc) - (c_i - c_j),
                            (m_i_enc - m_k_enc) - (c_i - c_k),
                        )
                        # print(candidate)
                        found_it = False
                        for l, msg in enumerate(list_msg):
                            if not msg == pow(str_to_int(MESSAGES[l]), e, candidate):
                                break
                        else:
                            # print(candidate)
                            return candidate
                print("FOUND NOTHING -> LOOKS LIKE A BAD IDEA")
                return -1

        json_send({"command": "distribute_secret"})
        res = json_recv()

        encrypted_msg = {}
        keys = {}
        secrets_prof = {}
        for prof in res["outputs"]:
            encrypted_msg[prof] = res["outputs"][prof][:-1]
            ## Finding n.
            keys[prof] = find_n(encrypted_msg[prof])
            secret_enc = res["outputs"][prof][-1]
            secrets_prof[prof] = secret_enc

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
        secret_decoded = int.to_bytes(secret, 32).decode()
        print(secret_decoded)

        json_send({"command": "vote"})
        json_recv()
        votes = {}
        for prof in keys:
            # print(keys[prof])
            vote = json.dumps({"excommunicate": False, "secret": secret_decoded})
            print(vote)
            vote = vote.encode()
            votes[prof] = pow(bytes_to_long(vote), 17, keys[prof])
        json_send({"command": "adjudicator", "votes": votes})
        res = json_recv()
        if "flag" in res:
            print(res["flag"])
            break
    except:
        pass
