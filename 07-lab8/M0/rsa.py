from Crypto.Util import number
from Crypto.Random import random

import math


def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)

    """
    e = 65537
    flag = False
    while not flag:
        p, q = number.getPrime(nbits // 2), number.getPrime(nbits // 2)
        if (not p == q) and number.GCD(p - 1, e) == 1 and number.GCD(q - 1, e):
            flag = True
    N = p * q
    d = number.inverse(e, (p - 1) * (q - 1))
    return (N, e), (N, d), (p, q)


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """
    N, e = pk
    return (m ** (e)) % N


def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """
    N, d = sk
    return pow(c, d, N)
