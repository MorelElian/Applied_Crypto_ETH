#!/usr/bin/env python

from Crypto.Hash import SHA256, HMAC, SHA384
from Crypto.Cipher import AES

import secrets


class CBC_HMAC:
    def __init__(
        self,
        enc_key_len: int = 16,
        mac_key_len: int = 16,
        key: bytes = None,
        tag_len: int = 16,
    ):
        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = tag_len

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

        pt_padded = pt + to_add * len_to_add
        return pt_padded

    def _remove_pt_padding(self, pt: bytes):
        """Return unpadded plaintext"""
        if (not pt[-1] < 17) or int.from_bytes(pt[:-1]) == 0:
            raise ValueError("Bad decryption")

        return pt[: -pt[-1]]

    def compute_AL(self, a):
        len_A = int.to_bytes(len(a) * 8, 8)
        return len_A

    def encrypt(self, pt: bytes, add_data: bytes = b"", iv: bytes = None):
        """Compute ciphertext and MAC tag.

        Keyword arguments:
        pt       -- plaintext
        add_data -- additional data
        iv       -- initialization vector
        """
        if iv is None:
            # Choose random IV.

            iv = secrets.token_bytes(16)
        pt_padded = self._add_pt_padding(pt)
        al = self.compute_AL(add_data)
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pt_padded)
        h = HMAC.new(self.mac_key, digestmod=SHA256)
        h.update(add_data + iv + ct + al)
        tag = h.digest()
        print((iv + ct + tag[:16]).hex())

        return (iv + ct) + tag[:16]

    def decrypt(self, ct_tag: bytes, add_data: bytes = b"", digestmod=SHA256):
        h = HMAC.new(self.mac_key, digestmod=digestmod)
        ct = ct_tag[: -self.tag_len]
        tag = ct_tag[-self.tag_len :]
        al = self.compute_AL(add_data)
        h.update(add_data + ct + al)
        mac = h.digest()[: self.tag_len]
        if not mac == tag:
            return "DATA HAS BEEN COMPROMISED"
        cipher = AES.new(self.enc_key, AES.MODE_CBC)
        pt_padded = cipher.decrypt(ct)
        pt_iv = self._remove_pt_padding(pt_padded)
        pt = pt_iv[16:]
        return pt


def main():
    test_key = bytes.fromhex(
        """
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        """
    )
    test_pt = bytes.fromhex(
        """
        41206369706865722073797374656d206d757374206e6f742062652072657175
        6972656420746f206265207365637265742c20616e64206974206d7573742062
        652061626c6520746f2066616c6c20696e746f207468652068616e6473206f66
        2074686520656e656d7920776974686f757420696e636f6e76656e69656e6365
        """
    )
    test_iv = bytes.fromhex("1af38c2dc2b96ffdd86694092341bc04")
    test_ad = bytes.fromhex(
        """
        546865207365636f6e64207072696e6369706c65206f66204175677573746520
        4b6572636b686f666673
        """
    )
    test_c = bytes.fromhex(
        """
        1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279
        a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2
        fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c8
        6e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59f
        bd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db
        652c3fa36b0a7c5b3219fab3a30bc1c4
        """
    )
    print("TEST C", test_c.hex())
    assert CBC_HMAC(16, 16, test_key).encrypt(test_pt, test_ad, test_iv) == test_c

    pt = b"Just plaintext\x02\x00"
    print(
        SHA256.new(data=CBC_HMAC(16, 16, test_key).encrypt(pt, iv=test_iv)).hexdigest()
    )

    key = bytes.fromhex(
        "41206c6f6e6720726561642061626f75742073797374656d64206973207768617420796f75206e65656420616674657220746865206c6162"
    )
    ct = bytes.fromhex(
        "bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab7df30af4ad0db52e"
    )
    ad = bytes.fromhex("")
    aead = CBC_HMAC(32, 24, key, tag_len=24)
    pt = aead.decrypt(ct, ad, digestmod=SHA384)
    print(pt)


if __name__ == "__main__":
    main()
