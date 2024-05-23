
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
PORT = 50222

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True
additional_characters = "{}[]()!@#$%^&*_+-=,.<>?;:'\"\\|~`"
# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"
ALPHABET = ascii_letters + digits + additional_characters
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
print("0" + hex(15)[1:])
print(bytes.fromhex("0"+ hex(15)[2:]))
old_message_length = 0
new_message_length = 0
length_prepad = 1
prepend_pad = 0
msg = run_command({"command" : "encrypt", "prepend_pad" : ""})["res"]
new_message_length = len(msg)
old_message_length = new_message_length

while new_message_length == old_message_length:
    old_message_length = new_message_length
    prepend_pad = (b'a' * length_prepad).hex()
    msg = run_command({"command" : "encrypt", "prepend_pad" : prepend_pad})["res"]
    
    new_message_length = len(msg)
    length_prepad+=1
recovered = b""
for i in range(16):
     
    for letter in ALPHABET:
        
        trying = letter.encode() + recovered + bytes.fromhex("0"+ hex((15-i) % 16)[2:]) * ((15-i) % 16) + b'a'*(length_prepad+i)
       
        msg = run_command({"command":"encrypt", "prepend_pad" : trying.hex()})["res"]
        
        if msg[:32] == msg[-32:]:
            print("YES : ",letter)
            recovered = bytes(letter.encode()) + recovered
            
            break
for i in range(16):
    for letter in ALPHABET:
        trying = letter.encode() + recovered + bytes.fromhex("0"+ hex((15-i) % 16)[2:]) * ((15-i) % 16) + b'a'*(length_prepad+i)
        msg = run_command({"command":"encrypt", "prepend_pad" : trying.hex()})["res"]
        if msg[:32] == msg [-64:-32]:
            print("YES : ",letter)
            recovered = bytes(letter.encode()) + recovered
            
            break

print(recovered)
for i in range(16):
    for letter in ALPHABET:
        trying = letter.encode() + recovered + bytes.fromhex("0"+ hex((15-i) % 16)[2:]) * ((15-i) % 16) + b'a'*(length_prepad+i)
        msg = run_command({"command":"encrypt", "prepend_pad" : trying.hex()})["res"]
        if msg[:32] == msg [-96:-64]:
            print("YES : ",letter)
            recovered = bytes(letter.encode()) + recovered
            
            break
for i in range(16):
    for letter in ALPHABET:
        trying = letter.encode() + recovered + bytes.fromhex("0"+ hex((15-i) % 16)[2:]) * ((15-i) % 16) + b'a'*(length_prepad+i)
        msg = run_command({"command":"encrypt", "prepend_pad" : trying.hex()})["res"]
        if msg[:32] == msg [-128:-96]:
            print("YES : ",letter)
            recovered = bytes(letter.encode()) + recovered
            
            break
print(recovered)


