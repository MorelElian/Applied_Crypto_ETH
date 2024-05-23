#!/usr/bin/env python

from Crypto.Hash import SHA256

...


class CBC_HMAC:
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = 32

        # a correctly sized key must always be provided by the caller
        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")

        self.mac_key = key[: self.mac_key_len]
        self.enc_key = key[-self.enc_key_len :]
        self.block_len = 16

    def _add_pt_padding(self, pt: bytes):
        """Return padded plaintext"""
        if not len(pt) % 16:
            to_add = int(16).to_bytes(1)
            len_to_add = 16
        else:
            to_add = int.to_bytes(16 - len(pt) % 16)
            len_to_add = 16 - (len(pt) % 16)
        print(to_add)
        print(int.from_bytes(to_add))
        pt_padded = pt + to_add * len_to_add
        return pt_padded

    def _remove_pt_padding(self, pt: bytes):
        """Return unpadded plaintext"""
        if (not pt[-1] < 17) or int.from_bytes(pt[:-1]) == 0:
            raise ValueError("Bad decryption")

        return pt[: -pt[-1]]

    def compute_AL(self, a: str):
        len_A = int.to_bytes(len(a) * 8, 8)
        return len_A


def main():
    aead = CBC_HMAC(16, 16, b"".join(bytes([i]) for i in range(32)))

    pt = b"Just plaintext\x02\x00"
    print(aead._add_pt_padding(pt))
    assert aead._remove_pt_padding(aead._add_pt_padding(pt)) == pt
    print(SHA256.new(data=aead._add_pt_padding(pt)).hexdigest())
    tab = [
        "a",
        "a 23 bytes long string",
        "64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes",
    ]
    for string in tab:
        print(aead.compute_AL(string).hex(), end=",")


if __name__ == "__main__":
    main()
