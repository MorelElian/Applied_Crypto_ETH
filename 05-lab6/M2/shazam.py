#!/usr/bin/env python3


def blockify(data: bytes, blocksize: int):
    print(len(data))
    assert len(data) % blocksize == 0
    return [
        int.from_bytes(data[i : i + blocksize], "big")
        for i in range(0, len(data), blocksize)
    ]


def left_shift_circular(word: int, shift_amount: int = 1) -> int:
    return ((word << shift_amount) | (word >> (32 - shift_amount))) & 0xFFFFFFFF


BLOCK_SIZE_BYTES = 64
WORD_SIZE_BYTES = 4
LONG_SIZE_BYTES = 8


class SHAzam:
    def __init__(self):
        self.hash = [0x49276D20, 0x62756C6C, 0x65747072, 0x6F6F6620, 0x3F213F21]
        self.buffer = b""
        self.length = 0

    def _compress(self, data):
        W = blockify(data, 4)
        W += [0] * (80 - len(W))
        assert len(W) == 80
        for t in range(16, 80):
            W[t] = left_shift_circular(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16])

        A, B, C, D, E = (
            self.hash[0],
            self.hash[1],
            self.hash[2],
            self.hash[3],
            self.hash[4],
        )
        for t in range(0, 80):
            temp = (
                left_shift_circular(A, 5) + self._f(t, B, C, D) + E + W[t] + self._K(t)
            )
            temp &= 0xFFFFFFFF
            A, B, C, D, E = temp, A, left_shift_circular(B, 30), C, D

        self.hash[0] = (self.hash[0] + A) & 0xFFFFFFFF
        self.hash[1] = (self.hash[1] + B) & 0xFFFFFFFF
        self.hash[2] = (self.hash[2] + C) & 0xFFFFFFFF
        self.hash[3] = (self.hash[3] + D) & 0xFFFFFFFF
        self.hash[4] = (self.hash[4] + E) & 0xFFFFFFFF

    def _K(self, t):
        if 0 <= t < 20:
            return 0x5A827999
        elif 20 <= t < 40:
            return 0x6ED9EBA1
        elif 40 <= t < 60:
            return 0x8F1BBCDC
        elif 60 <= t < 80:
            return 0xCA62C1D6
        else:
            raise ValueError(f"Invalid value for t={t} (Must be 0 <= t < 80)")

    def _f(self, t, B, C, D) -> int:
        if 0 <= t < 20:
            return (B & C) | ((~B) & D)
        elif 20 <= t < 40:
            return B ^ C ^ D
        elif 40 <= t < 60:
            return (B & C) | (B & D) | (C & D)
        elif 60 <= t < 80:
            return B ^ C ^ D
        else:
            raise ValueError(f"Invalid value for t={t} (Must be 0 <= t < 80)")

    def update(self, data: bytes) -> None:
        """Takes `data` and updates the hash state

        This function take bytes as input and appends them to `buffer`. If the length of `buffer` is now greater
        than or equal to BLOCK_SIZE_BYTES, the buffer is split into blocks of size BLOCK_SIZE_BYTES and each full block is processed
        by using the `_compress` function. The last incomplete block (if any) becomes the new value of the buffer.
        If there is no such block, the buffer becomes empty.

        The instance member `self.length` helps you to keep track of the number of bytes being processed by the `_compress` function.

        """
        self.buffer += data
        block_buffer = []
        if len(self.buffer) >= BLOCK_SIZE_BYTES:
            block_buffer = [
                self.buffer[i : min(i + BLOCK_SIZE_BYTES, len(self.buffer))]
                for i in range(0, len(self.buffer), BLOCK_SIZE_BYTES)
            ]
        for i in range(len(block_buffer) - 1):
            self._compress(block_buffer[i])
            self.length += BLOCK_SIZE_BYTES
        if block_buffer and len(block_buffer[-1]) == BLOCK_SIZE_BYTES:
            self._compress(block_buffer[-1])
            self.length += BLOCK_SIZE_BYTES
            self.buffer = b""
        elif block_buffer:
            self.buffer = block_buffer[-1]

    def digest(self):
        """Returns the digest of the data

        This function applies the final padding to the data and extracts the resulting hash.
        For the padding, use the scheme shown here: https://datatracker.ietf.org/doc/html/rfc3174#section-4.
        The length of the message mentioned in the rfc is in bits (not bytes).
        Then, use the update function with the computed padding.
        To extract the hash, take `self.hash` and convert each integer into a 4-byte word. Then, concatenate them to obtain a single
        20-byte string.
        """
        len_message = self.length + len(self.buffer)
        print(self.buffer)
        print(len_message)
        self.buffer += b"\x80"
        if len(self.buffer) % 64 > 55:
            self.buffer += b"\x00" * (128 - 8 - (len(self.buffer) % 64))
        else:
            self.buffer += b"\x00" * (64 - 8 - (len(self.buffer) % 64))
        l_twoword = int.to_bytes(len_message * 8, length=2)
        print(l_twoword)
        self.buffer += b"\x00" * 6 + l_twoword
        print(self.buffer)
        print(len(self.buffer))
        self.update(b"")
        final_hash = b""
        for hash in self.hash:
            final_hash += int.to_bytes(hash, 4)
        return final_hash


if __name__ == "__main__":
    sha = SHAzam()

    # Add assert for compression function
    sha.update(b"DC is better than Marvel anyway!")
    # assert sha.digest().hex() == "3cd46b5888ee08dc695cd77003e1ebe4cd4d552f"

    sha = SHAzam()
    sha.update(b"I'm sorry Stan Lee, I actually love you please don't hurt me")
    print(f"Your flag is: {sha.digest().hex()}")

    # An additional assert on a message that is longer than one block.
    sha = SHAzam()
    sha.update(
        b"ChatGPT wrote this poem about SHA for me: SHA, a hash function secure and strong; Transforms data, strings long; Into fixed-length digests, so compact; That even small changes, impact exact A cryptographic tool, with many uses; Securing data, against abuses; Digital signatures, passwords stored; SHA, a reliable guard, adored"
    )
    assert sha.digest().hex() == "ad1743d89870905b8b045a517813c4f5c3eefd64"
    print("success is on the way")
