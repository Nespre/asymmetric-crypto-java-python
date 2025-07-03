# Cryptography Playground
This project explores multiple cryptographic algorithms — RSA, ElGamal, and ECDSA — through manual implementations and secure library-based approaches, in both Java and Python.

The goal is to deeply understand cryptographic principles by implementing everything from scratch before applying industry-grade libraries like BouncyCastle and Python cryptography.
<br><br>

## Index
- [Available Scripts](#available-scripts)
- How It Works
- How to Use
- Parameters
- Contributing
- License
<br><br>

## Available Scripts
### Java - Manual Implementations
**`ELGamalMain.java`**
- Implements ElGamal encryption from scratch.
- **Input**: "This an lesson about Cryptography" <br>**Output**: Encrypted BigIntegers + original message restored.

**`RSAMain.java`**
- Implements RSA manually, including prime generation, public/private keys, encryption and decryption.
- Input: "This an lesson about Cryptography" <br>Output: Encrypted BigInteger + Decrypted message.
<br>
### Java - Practical RSA & ECDSA with Libraries (BouncyCastle)
**`Main.java`**
- Full-feature cryptographic suite:
	- ✔️RSA encryption/decryption
	- ✔️RSA digital signatures (PSS + PKCS#1 v1.5)
	- ✔️ECDSA signatures with verification
- All done with security-focused libraries including BouncyCastle.
- Outputs shown in both **Hex** and **Base64**.

### Python - Secure Crypto (Library-based)
**`RSA.py`**
- RSA encryption/decryption using cryptography primitives.
- Securely handles message encoding and decoding.

**`ELGamal.py`**
- ElGamal encryption using secure libraries (PyCryptodome / cryptography).
- Converts between bytes and strings, encrypts and decrypts securely.

<br>
