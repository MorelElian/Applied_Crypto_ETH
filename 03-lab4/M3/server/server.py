import secrets
import random
from string import ascii_letters
from boilerplate import CommandServer, on_command

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

MESSAGES = [
    "Pad to the left",
    "Unpad it back now y'all",
    "Game hop this time",
    "Real world, let's stomp!",
    "Random world, let's stomp!",
    "AES real smooth~",
]

# Pad all the messages to 32 bytes so that they are all at the same length
MESSAGES = [msg.ljust(32) for msg in MESSAGES]


def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))


def generate_secret() -> str:
    return "".join(secrets.choice(ascii_letters) for _ in range(32))


class UptownFunkyServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)
        self.score = 0
        self.secret_message = generate_secret()
        self.secret_message = "c" + self.secret_message[1:]
        print(self.secret_message)
        # Securely initialize randomness using the secrets library
        random.seed(secrets.choice(MESSAGES))

        super().__init__(*args, **kwargs)

    @on_command("encrypt")
    def handle_encrypt(self, msg):
        try:
            ptxt = bytes.fromhex(msg["msg"]) + self.secret_message.encode()
            iv = random.randbytes(16)
            # print("PTXT IV", ptxt.hex(), iv.hex())
            # print("XOR", xor(iv, ptxt).hex())
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)

            ctxt = cipher.encrypt(pad(ptxt, 16))

            self.send_message({"ctxt": ctxt.hex(), "iv": iv.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("guess")
    def handle_guess(self, msg):
        try:
            guess = msg["guess"]
            if guess == self.secret_message:
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"error": "Peace out!"})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    UptownFunkyServer.start_server("0.0.0.0", 50403, flag=flag)
