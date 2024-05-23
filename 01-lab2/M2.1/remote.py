
#!/usr/bin/env python3

import json
import socket
from Crypto.Cipher import AES
import secrets
from Crypto.Util.Padding import pad, unpad
from string import ascii_letters, digits

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50221

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"
ALPHABET = ascii_letters + digits
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
for i in range(5):
    old_message_length = 0
    new_message_length = 0
    length_prepad = 1
    prepend_pad = 0
    msg = run_command({"command" : "encrypt", "prepend_pad" : ""})["res"]
    new_message_length = len(msg)
    old_message_length = new_message_length
    print(msg)
    while new_message_length == old_message_length:
        old_message_length = new_message_length
        prepend_pad = (b'a' * length_prepad).hex()
        msg = run_command({"command" : "encrypt", "prepend_pad" : prepend_pad})["res"]
        print(msg)
        new_message_length = len(msg)
        length_prepad+=1

    print(old_message_length,new_message_length) 
    for letter in ALPHABET:
        print(letter)
        trying = letter.encode() + b"\x0f" * 15 + b'a'*length_prepad
        msg = run_command({"command":"encrypt", "prepend_pad" : trying.hex()})["res"]
        print(msg,len(msg))
        if msg[:32] == msg[-32:]:
            print("YES : ",letter)
            msg = run_command({"command" : "solve", "solve" : letter})
            print(msg)
            break
line = fd.readline()
print(line)


