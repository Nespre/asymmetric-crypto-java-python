# Cryptography Playground
This project explores multiple cryptographic algorithms — RSA, ElGamal, and ECDSA — through manual implementations and secure library-based approaches, in both Java and Python.

The goal is to deeply understand cryptographic principles by implementing everything from scratch before applying industry-grade libraries like BouncyCastle and Python cryptography.
<br><br>


## Index
- [Available Scripts](#available-scripts)
- [How It Works](#how-it-works)
- [How to Use](#how-to-use)
- [Parameters](#parameters)
- [Contributing](#contributing)
- [License](#license)
<br><br>


## Available Scripts
### Java - Manual Implementations
**`ELGamalMain.java`**
- Implements ElGamal encryption from scratch.
- **Input**: "This an lesson about Cryptography" <br>**Output**: Encrypted BigIntegers + original message restored.

**`RSAMain.java`**
- Implements RSA manually, including prime generation, public/private keys, encryption and decryption.
- Input: "This an lesson about Cryptography" <br>Output: Encrypted BigInteger + Decrypted message.

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
<br><br>


## How It Works
### Java - Manual
1. A custom key pair is generated (RSA or ElGamal).
2. The string message is converted to a `BigInteger`.
3. Encryption is performed using modular exponentiation.
4. Decryption reverses the process and restores the original message.

### Java - Library-Based Crypto
1. Uses BouncyCastle for RSA/ECDSA key generation and secure crypto operations.
2. Message is converted to bytes, encrypted/decrypted.
3. Digital signatures (RSA + ECDSA) are generated and verified.

### Python
1. Cryptographic keys are securely generated with the `cryptography` module.
2. Messages are encoded into bytes.
3. Encryption, decryption, and signature processes are securely handled using trusted libraries.
<br><br>


## How to Use
1. Clone the repository: <br>`git clone https://github.com/YOUR_USERNAME/cryptography-playground.git`
2. Navigate to the project directory: <br>`cd cryptography-playground`

### Java
* Compile and run the desired script: <br>`javac RSAMain.java` <br>`java RSAMain`
* Or for the advanced project: <br>`javac Main.java` <br>`java Main`

Make sure to include all `.java` dependencies in the same directory or classpath.

### Python
* Install requirements (if any) and run: <br>`pip install cryptography pycryptodome` <br>`python RSA.py` <br>`python ELGamal.py`
<br><br>


## Parameters
No command-line parameters are required — messages are defined directly in the code for clarity. You can change them manually in the scripts.
<br><br>


## Contributing
Feel free to contribute! Open a pull request or create an issue to suggest improvements or new crypto features. Collaboration is welcome — especially if you're experimenting with new algorithms or padding schemes.
<br><br>


## License
This project is licensed under the MIT License. See LICENSE for more details.
<br>

---
> **Disclaimer:** This project is for educational and academic purposes only.  
> It is not intended for use in production systems or handling real-world sensitive data.