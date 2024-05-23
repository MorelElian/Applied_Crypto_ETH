a = bytes.fromhex(
    "9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0"
)
b = bytes.fromhex(
    "b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4"
)


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


# Split the plaintext into crib-sized blocks
crib = b"flag{"
crib_l = len(crib)

a_blocks = [a[i : i + crib_l] for i in range(0, len(a), crib_l)]
b_blocks = [b[i : i + crib_l] for i in range(0, len(b), crib_l)]

# Use the crib to iteratively reveal parts of the plaintext
pt = b""
for a_b, b_b in zip(a_blocks, b_blocks):
    ks = xor(b_b, crib)
    crib = xor(a_b, ks)
    pt += crib

print(pt)
