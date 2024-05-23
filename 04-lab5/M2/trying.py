from Crypto.Hash import MD5, HMAC, SHA256, SHA1

hash = "9fb7009f8a9b4bc598b4c92c91f43a2c"
compteur = 0
with open("rockyou.txt") as file:
    for line in file.readlines():
        compteur += 1

        trying = MD5.new(line.encode()[:-1]).digest().hex()
        if compteur % 10000 == 0:
            print(compteur)

        if trying == hash:
            print(line, trying)
            break
