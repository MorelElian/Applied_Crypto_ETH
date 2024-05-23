from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad


class StrangeCBC:
    def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
        """Initialize the CBC cipher."""

        if iv is None:
            iv = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
            pass

        self.iv = iv
        self.key = key
        self.block_length = block_length
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        self.constant = 1336
        # self.constant = self.constant.to_bytes(self.block_length, byteorder="big")

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV


        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
        # reforming plaintext to do the XORING
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        print("PT : ", plaintext)
        padded_plaintext = pad(plaintext, self.block_length)
        print("pad_plain", padded_plaintext)
        padded_xor_plaintext = b""
        for i in range(0, len(padded_plaintext), 16):
            int_block = int.from_bytes(padded_plaintext[i : i + self.block_length])
            result = int_block.__xor__(1336).to_bytes(
                self.block_length, byteorder="big"
            )
            padded_xor_plaintext += result
        print("padded_xor_plaintext", padded_xor_plaintext)
        ciphertext = cipher.encrypt(padded_xor_plaintext)
        cipher_b = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        print("decrypted", cipher_b.decrypt(ciphertext))
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        cipher_b = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        print("CT:", ciphertext)
        pt_pad = cipher_b.decrypt(ciphertext)
        print("PT_PAD", pt_pad)
        pt = b""
        for i in range(0, len(pt_pad), 16):
            pt += (
                self.constant.__xor__(int.from_bytes(pt_pad[i : i + self.block_length]))
            ).to_bytes(self.block_length, byteorder="big")
        print(pt)
        plaintext = unpad(pt, self.block_length)
        return plaintext


def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        print("TURN")
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
        "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
        "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
        "3fd46234ff7b62ad365d1db13bb249721b"
    )
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")


if __name__ == "__main__":
    main()
