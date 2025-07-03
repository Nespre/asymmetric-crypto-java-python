from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
# getPrime(bits) - generate a secure prime number with N bits
# inverse(a, p) - inverse of a modulo p in robust way - avoids error with long numbers
# bytes_to_long(b) - convert bytes to integer
# long_to_bytes(n) - convert integer to bytes
from random import randint

def verify_generator(g: int, p: int) -> int:
    while True:
        if pow(g, 2, p) != 1 and pow(g, (p - 1) // 2, p) != 1:
            return g
        else:
            g = randint(1, p - 2)

def generate_keys_elgamal(bits: int = 2048) -> list:
    if bits < 2048:
        raise ValueError("Key size should be at least 2048 bits for security")
    p: int = getPrime(bits)          # big prime number
    g: int = 2                       # generator of the group commonly used
    g: int = verify_generator(g, p)
    x: int = randint(1, p-2)      # private key, x ∈ [1, p−2]
    y: int = pow(g, x, p)            # public key, y = g^x mod p
    return [p, g, x, y]

def elgamal_encrypt(byte_message: bytes,
                    p: int,
                    g: int,
                    y: int) -> list[int]:
    # m - message to encrypt
    m = bytes_to_long(byte_message)
    if m >= p:
        raise ValueError(f"Message must be shorter than p. m:{m} - p:{p}")
    # generate random k ∈ [1, p−1]
    k: int = randint(1, p-1)
    # a = g^k mod p
    a: int = pow(g, k, p)
    # b = (m * y^k) mod p
    b: int = (m * pow(y, k, p)) % p
    # [a, b] - represents the encrypted message
    return [a, b]

def elgamal_decrypt(ciphertext: list,
                    p: int,
                    x: int) -> bytes:
    a, b = ciphertext
    # s = a^x mod p
    s: int = pow(a, x, p)
    # s^-1 = 1/s mod p
    s_inv: int = inverse(s, p)
    # get original message, m = (b * s^-1) mod p
    m: int = (b * s_inv) % p

    # convert message to bytes
    decrypted_message = long_to_bytes(m)

    if decrypted_message is None or len(decrypted_message) == 0:
        raise ValueError ("Decryption returned None or empty bytes!")

    return decrypted_message

if __name__ == "__main__":
    message: str = "This an lesson about Cryptography"
    byte_message: bytes = message.encode('utf-8')
    p, g, x, y = generate_keys_elgamal()

    # encrypt message
    ciphertext: list[int] = elgamal_encrypt(byte_message, p, g, y)

    # decrypt message
    decrypted_message: bytes = elgamal_decrypt(ciphertext, p, x)
    # bytes to string
    original_message: str = decrypted_message.decode('utf-8')

    print(f"Message \t\t\t{message}")
    print(f"Encrypted message \t{ciphertext}")
    print(f"Decrypted message \t{original_message}")
    print(f"Success \t\t\t{message == original_message}")




