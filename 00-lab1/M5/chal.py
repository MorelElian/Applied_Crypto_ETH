from itertools import cycle
from bigrams import freq

KEY_STREAM = b" REDACTED "

CHALLENGE_PLAINTEXT = b" REDACTED "
global full_key


def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])


only_accepted = [
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    " ",
    ".",
    ",",
    "{",
    "}",
]
for char in only_accepted:
    freq.append(" " + char)
    freq.append(char + " ")
dict_accepted = {a.encode(): 0 for a in only_accepted}
ctxt = xor(KEY_STREAM, CHALLENGE_PLAINTEXT)
print(ctxt.hex())
CHALLENGE_CIPHERTEXT = "4d68f21bf515dce57ee78a66724c4d9f5416fadc8d417652d8cbe1ce8080fc132bec643cc30460f9561669cc16d2786af846a12c611c6dc150504a22b18c95c9e34dd8f0efb1aa0fe0ec8a996b03ee56b27bac5bbc70413a5fa29de92dfee2802735e334c44f026e6cbbf9b40f65a0faf3bf11ddfb75083b417eb306f317c4f07bf88c27714555994045a9c8cf517042dccaf4c98e82a50336bc7836911325ea4b107e8942ce752fb450ba29660024da43045725ba8c9fc0ea52d6e0eeebf940effd8a997c03e405bb70e25eb138153d5ca29cf22dfee6837e23ac2dc5161c723ebbbce71862b3bfeabb0698a86a097e0465a012ea0dc4ea73fb9b746409559f5953fa899a42224fc4dbb5c4869eb41530e86921c55729e01e1d3bca59ca6562b646f86e650061c740044d6db6dfd4d1fb4099feefabbe5be9be80df281fe940f77ee940b23f473614a29cf22db0ad836637ab7fc259197473b1f5f71a63e5b8fdfe16c6ed7f157e4026b318ba0dcde132f48b77784c4b82524efd898054225a8cd3fac9808fb0002afd6e3cc51e23ae4d0679da42cf647aac5cbb20320b6dc54d415163ffcd8785e050dafaa6e5bc4ee2f6cfda6707f448b935ef58ab7057371ae39cee29bde6836374b436d55e55676cbaa4e11e63a6a3b8bf0cd5e46712725728f218f314cce873e58e7e3c094e9e5244ec898e127054d8d1e7879c9aae1523f12c3ad80728eb4c5376c855ce7961bd15bc2f614866d0404a0338acc99089b351d1fbf9e5b44af5f680dd2806e05cf774e055aa27152652e7c8fe2dbaf885733dac31815913216ab7b0b41768abbdecb642dbee3e0875406fa402fe0cc4e832e58d737f5b4ad81742e1cccf596348c5cdfececf8ba4112ff56238c51e2fe01e1a75df59ca666aab15b8217d036ddb42044522ad8c87d1e14cd7f5f9e5b649a1fd87d87a0ae251b267ff19b13854261ae39aff68ace8966235b73ac5161c6f3eabbdf15b6eacaaf0bb10c0ed6615350472ba0eba0ad1f67bf98574305a5199425aed898d57224fc4ccf0c2cf8db41130fd6f2dd40533ae521c75ce16c9622fb55aa62b320e6bc705504b28ffc98cc4fe4cd7f3feacb641a1ea80996a0ea156a276ef5cb623532756acc8ee20bbe3ca2720ab3a81521c726abebbf71e7ee5b8fdaa15d1ed7041784b68a10ef90cd1ed64f2c268734a4c844553e7ca8a412254ca9ee1cf8aceaf0430f5623ec25721fc5b5377c05dc37c76f841bb6e700d24d850485724afc091d6b34adfb2feadbc0fedfb81de7c03a14ab135f851a0705e3743f587e82cf0ad926f21b07fc75f1b6577b1b2b41662b7bfb8ac07c4ed7f157e4026a11fe810cbe361b78c66625b56814416edc6985c224fc4dbb5d7809daf1920f06979dd122ee94a1b688959c0307bb050f425771173da57400f6dacc59ac6f605cef7aaa6b841a1ea8ed26d4bf54db235eb4ba031413749f6c8f927b3e0896974a736d75f066e6cffbaf25b6ca9b6b8aa0ad1a87a08685067bc08ff0a8ba466ff8727624c58855858a9dd875b711bd8dbe6d3cf99b30229ef2c30c25734e65f073bc05086712faa50a42b731c61d10557573fb6c29385fc46dae7f8b6f946efbe9bd16d4bf149b67ce24da028417e1ae386fe68aae5832730aa2cd5571b627bffb7f10f7aa0bff6fe01dbfa6c04685469bc0ff317c2a471ff8375714a4d934545a9c09c12631bc1cbf9d3869eb01562f36a79c51f25ae551662de59d4742fb450ba2966002895514c466db4c98dd2fc57ddb2e6a0ad5be4ec9c997f02ed49f779e557a07040221aeb86ba3cb6e8c67435ae3a814114783ea8bce0132da7b5ecb642dbeb7d14695663bc08ff0a85eb74b7966f75094a82455fe7cec1126457cdd9eec19d8bad0527f26f2091162eef520a68c045867f61f847b13e770970d041044828a6df80d7f644d4ef"
challenge_bytes = bytes.fromhex(CHALLENGE_CIPHERTEXT)
print(len(challenge_bytes), len(CHALLENGE_CIPHERTEXT))

full_key = b""
for j in range(0, 120, 2):
    encoded = []
    for i in range(0, len(challenge_bytes) - 120, 120):
        print(i, int.to_bytes(challenge_bytes[j + i]))
        encoded.append(
            int.to_bytes(challenge_bytes[j + i])
            + int.to_bytes(challenge_bytes[j + i + 1])
        )

    def trying_bigram(double_byte, full_key, encoded):
        for fr in freq:
            print("HERE IN FFR SEARCH")
            key = xor(double_byte, fr[0].encode())
            flag = True
            tab_trying = []
            for encode in encoded:
                trying_encode = xor(key, encode)
                # print(trying_encode)
                tab_trying.append(trying_encode)
                if (not int.to_bytes(trying_encode[0]) in dict_accepted) or (
                    not int.to_bytes(trying_encode[1]) in dict_accepted
                ):
                    flag = False
                    break
            if flag:
                print(tab_trying)
                full_key += key
                print("FOUND IT")

                return full_key

        if flag == False:
            print("DON'T FOUND IT FOR", double_byte)

            return False

    for encode in encoded:
        trying_full_key = trying_bigram(encode, full_key, encoded)
        if trying_full_key:
            full_key = trying_full_key
            print(full_key)

            break


print(xor(challenge_bytes, full_key).decode())
