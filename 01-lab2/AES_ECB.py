with open("aes.data") as file:
    maxi = 0
    for line in file.readlines():
        dico = dict()
        line = bytes.fromhex(line)
        tab = [line[i : i + 16] for i in range(0, len(line), 16)]
        for block in tab:
            if not int.from_bytes(block) in dico:
                dico[int.from_bytes(block)] = 1
            else:
                dico[int.from_bytes(block)] += 1
        max_key = max(dico, key=dico.get)
        if dico[max_key] > maxi:
            maxi = dico[max_key]
            maxi_line = line.hex()
            print(maxi_line, dico[max_key])
