# Generer des clés
# decrypter sur genre 500 seed différentes, 
# voir
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")
def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key
with open("flag.enc","r") as file:
    ciphertext = file.readline()
    for i in range(65535):
        trying_key = generate_aes_key(i,16)
        cipher = AES.new(trying_key,AES.MODE_CBC,iv)
        plaintext = cipher.decrypt(bytes.fromhex(ciphertext))
        try:
            print(plaintext.decode())
            print(i)
        except:
            continue