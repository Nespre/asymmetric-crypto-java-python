from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import typing

def generate_key_RSA(bits=2048):
    if bits < 2048:
        raise ValueError("Key size should be at least 2048 bits for security")

    private_key: rsa = rsa.generate_private_key(
        public_exponent=65537, # Minimum for average security
        key_size=bits,
        backend=default_backend() # Specifies the default cryptographic backend for key generation
    )
    public_key: rsa = private_key.public_key()
    return [private_key, public_key]

def encrypt_message(plaintext: bytes, public_key: rsa):
    try:
        cyphertext = public_key.encrypt(
            plaintext,  # message to encrypt
            padding.OAEP(  # complex recommended padding scheme for RSA - prevents class attacks
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                # standard algorithm for generating the byte mask within OAEP - adaptive attacks resistance
                algorithm=hashes.SHA256(),  # scheme security - collision resistance
                label=None)  # ignore
        )
        return cyphertext
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

def decrypt_message(ciphertext: bytes, private_key: rsa):
    try:
        decrypted = private_key.decrypt(
            ciphertext,         # message to decrypt
            padding.OAEP(       # complex recommended padding scheme for RSA - prevents class attacks
                mgf=padding.MGF1(algorithm=hashes.SHA256()),    # standard algorithm for generating the byte mask within OAEP - adaptive attacks resistance
                algorithm=hashes.SHA256(),                      # scheme security - collision resistance
                label=None)                                     # ignore
        )
        return decrypted
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

if __name__ == '__main__':
    message: str = "This an lesson about Cryptography"
    byte_message: bytes = message.encode('utf-8')
    private_key, public_key = generate_key_RSA()
    ciphertext: bytes = encrypt_message(byte_message, public_key)
    decrypted_text: bytes = decrypt_message(ciphertext, private_key)
    original_text: str = decrypted_text.decode('utf-8')

    print(f'Message \t\t{message}')
    print(f'Cyphertext \t\t{ciphertext}')
    print(f'Decrypted text \t{original_text}')
    print(f'Is equal \t\t{message == original_text}')
