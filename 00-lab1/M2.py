hex_encoded = (
    "210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002"
)
byte = bytes.fromhex(hex_encoded)
print(byte)
for i in range(0, 256):
    a = bytes([i])
    str_tent = b""
    for b in byte:

        try:
            str_tent += bytes([b.__xor__(i)])
        except:
            continue
    print(str_tent.decode())
