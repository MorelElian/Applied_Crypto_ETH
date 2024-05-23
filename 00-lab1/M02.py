from Crypto.Hash import SHA256

string = b"LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteurs."
hash_obj = SHA256.new()
# SHA256.new(data=b'hi').hexdigest()
tab = [string[i : i + 16] for i in range(0, len(string), 16)]

for word in tab:
    print(word[-1])
    hash_obj.update((word[-1].to_bytes()))

print(hash_obj.hexdigest())
