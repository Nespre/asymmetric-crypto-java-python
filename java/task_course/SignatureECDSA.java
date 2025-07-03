import java.security.*;

/**
 * Provides ECDSA (Elliptic Curve Digital Signature Algorithm) signature generation and verification functionality.
 * <p>
 * This class supports creating digital signatures using a private key and verifying signatures
 * using a corresponding public key with SHA-256 hashing and the Bouncy Castle (BC) security provider.
 */
public class ECDSASignature {

    /**
     * Signs the given message using ECDSA with SHA-256 and the Bouncy Castle provider.
     * <p>
     * This method creates a digital signature for the provided message using the specified
     * elliptic curve private key and the "SHA256withECDSA" algorithm. It leverages the
     * Bouncy Castle ("BC") provider for cryptographic operations.
     * </p>
     *
     * @param message the byte array representing the message to be signed; must not be {@code null}
     * @param privateKey the EC private key used to generate the signature; must not be {@code null}
     * @return a byte array containing the ECDSA digital signature
     *
     * @throws NoSuchAlgorithmException if the "SHA256withECDSA" algorithm is not available
     * @throws NoSuchProviderException if the "BC" provider is not registered or available
     * @throws InvalidKeyException if the provided private key is invalid or incompatible
     * @throws SignatureException if an error occurs during the signing process
     *
     * @since 1.0
     *
     * <p><b>Example usage:</b></p>
     * <pre>{@code
     * Security.addProvider(new BouncyCastleProvider());
     *
     * CryptoUtils cryptoUtils = new CryptoUtils();
     * KeyPair ecKeyPair = cryptoUtils.generateECDSAKeyPair();
     * byte[] messageBytes = cryptoUtils.stringToBytes("Important message");
     *
     * ECDSASignature ecSigner = new ECDSASignature();
     * byte[] ecdsaSign = ecSigner.signature(messageBytes, ecKeyPair.getPrivate());
     * }</pre>
     */
    public byte[] signature(byte[] message, PrivateKey privateKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");   // Create Signature object with ECDSA with BC provider
        ecdsaSign.initSign(privateKey);                                                         // Initialize Signature object with private key
        ecdsaSign.update(message);                                                              // Update Signature object to sign message
        return ecdsaSign.sign();                                                                // Digital Signature
    }


    /**
     * Verifies the authenticity of a digital signature using ECDSA with SHA-256 and the Bouncy Castle provider.
     * <p>
     * This method validates whether a given signature was created using the corresponding private key
     * associated with the provided public key. It uses the "SHA256withECDSA" algorithm and the Bouncy Castle
     * security provider for cryptographic verification.
     * </p>
     *
     * @param message the original byte array message that was signed; must not be {@code null}
     * @param signature the byte array containing the digital signature to verify; must not be {@code null}
     * @param publicKey the EC public key used to verify the signature; must not be {@code null}
     * @return {@code true} if the signature is valid for the given message and public key, {@code false} otherwise
     *
     * @throws InvalidKeyException if the provided public key is invalid or incompatible
     * @throws NoSuchAlgorithmException if the "SHA256withECDSA" algorithm is not available
     * @throws NoSuchProviderException if the "BC" provider is not registered or available
     * @throws SignatureException if an error occurs during the signature verification process
     *
     * @since 1.0
     *
     * <p><b>Example usage:</b></p>
     * <pre>{@code
     * Security.addProvider(new BouncyCastleProvider());
     *
     * CryptoUtils cryptoUtils = new CryptoUtils();
     * KeyPair ecKeyPair = cryptoUtils.generateECDSAKeyPair(); - same key pair as above
     * byte[] messageBytes = cryptoUtils.stringToBytes("Important message"); - same message as above
     *
     * ECDSASignature ecSigner = new ECDSASignature();
     * boolean ecIsValid = ecSigner.verifySignature(messageBytes, ecdsaSign, ecKeyPair.getPublic());
     */
    public boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC"); // Create Signature object with ECDSA with BC provider
        ecdsaVerify.initVerify(publicKey);                                                      // Initialize Signature object with public key
        ecdsaVerify.update(message);                                                            // Update Signature object to verify original message
        return ecdsaVerify.verify(signature);                                                   // Verify Signature - returns true || false
    }
}