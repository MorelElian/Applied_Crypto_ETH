#!/usr/bin/env python3

import json
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50220

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================

fd = socket.create_connection((HOST if REMOTE else "localhost", PORT)).makefile("rw")


def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""

    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())


# ===================================================================================
#    Write Your Solution Below
# ===================================================================================
## la strat : lui demander des trucs de 1 à 16 pour reussir à avoir le bon padding,
## take the last encrypted block, xor it with  0xa0 0xa0 ...
## encrypter son message
## tester tant qu'on a pas le flag
padding_searched = b"\xa0" * 16
msg = b"flag, please!"
for i in range(16):
    prepend_pad = (b"a" * i).hex()

    response = run_command({"command": "encrypt", "prepend_pad": prepend_pad})
    encrypted_res = response["res"]
    bytes_encrypted = bytes.fromhex(encrypted_res)
    padding_block = bytes_encrypted[-16:]
    pot_key = int.from_bytes(padding_block).__xor__(int.from_bytes(padding_searched))

    pot_key = pot_key.to_bytes((pot_key.bit_length() + 7) // 8, byteorder="big")
    if len(pot_key) == 16:

        cipher = AES.new(pot_key, AES.MODE_ECB)
        padded_plaintext = pad(msg, cipher.block_size)
        to_send = cipher.encrypt(padded_plaintext)
        print(run_command({"command": "solve", "ciphertext": to_send.hex()}))

msg = run_command(
    {"command": "encrypt", "prepend_pad": b"flag, please!\x03\x03\x03".hex()}
)
flag_encrypted = bytes.fromhex(msg["res"])[:16]
print(run_command({"command": "solve", "ciphertext": flag_encrypted.hex()}))
