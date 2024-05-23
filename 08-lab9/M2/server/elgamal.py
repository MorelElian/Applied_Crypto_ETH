from typing import Tuple

from Crypto.PublicKey import ElGamal

from random import randint

from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse


class ElGamalImpl:
    @classmethod
    def decrypt(cls, key: ElGamal.ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """

        Y = bytes_to_long(c1)
        c = bytes_to_long(c2)
        if not (1 <= Y <= key.p - 1):
            raise ValueError
        Z_p = pow(Y, int(key.x), int(key.p))
        m = (c * inverse(int(Z_p), int(key.p))) % int(key.p)

        return long_to_bytes(m)

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """
        q = (int(key.p) - 1) // 2
        r = randint(0, q - 1)
        Y = pow(key.g, r, key.p)
        Z = pow(key.y, r, key.p)
        m = bytes_to_long(msg)
        return (long_to_bytes(int(Y)), long_to_bytes((Z * m) % key.p))
