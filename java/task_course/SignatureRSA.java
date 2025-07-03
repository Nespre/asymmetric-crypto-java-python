import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;


/**
 * Represents a utility class for generating RSA digital signatures using different padding schemes.
 * <p>
 * This class provides methods for creating digital signatures with both traditional PKCS1v15
 * and modern PSS (Probabilistic Signature Scheme) padding techniques.
 */
public class RSASignature {

    /**
     * Generates a digital signature for the given message using RSA with PKCS#1 v1.5 padding.
     *
     * @param message The data to sign; must not be {@code null}.
     * @param privateKey The RSA private key used for signing; must be valid.
     * @return A byte array containing the digital signature.
     *
     * @throws NoSuchAlgorithmException If the RSA signature algorithm is not available.
     * @throws InvalidKeyException If the private key is invalid.
     * @throws SignatureException If an error occurs during signing.
     *
     * <p><b>Example usage:</b></p>
     * <pre>{@code
     * RSASignature rsaSigner = new RSASignature();
     * byte[] signature = rsaSigner.defaultSignature(dataBytes, rsaKeyPair.getPrivate());
     * }</pre>
     */
    public byte[] defaultSignature(byte[] message, PrivateKey privateKey) throws Exception {
        return signWithPKCS1v15(message, privateKey);                           // Signature with default signature padding
    }
    /**
     * Generates a digital signature for the given message using RSA with PSS padding.
     * </p>
     * @param message The byte array of the message to be signed; must not be {@code null}.
     * @param privateKey The private key used to create the digital signature; must be a valid RSA private key.
     * @return A byte array representing the digital signature for the given message.
     *
     * @throws Exception If an error occurs during the signature generation - such as issues with the provided key or cryptographic operations.
     *
     * <p><b>Example usage:</b></p>
     * <pre>{@code
     * RSASignature rsaSigner = new RSASignature();
     * byte[] pkcs1Sign = rsaSigner.modernSignature(messageBytes, rsaKeyPair.getPrivate());
     */
    public byte[] modernSignature(byte[] message, PrivateKey privateKey) throws Exception {
        return signWithPSS(message, privateKey);                                // Signature with modern signature padding
    }

    /**
     * Signs the given message using RSA with SHA-256 and PKCS#1 v1.5 padding.
     * <p>
     * This method creates a {@link Signature} instance with the algorithm
     * "SHA256withRSA" (PKCS#1 v1.5 padding) and uses the provided private key
     * to generate the digital signature.
     * </p>
     * @param message The data to sign; must not be {@code null}.
     * @param privateKey The RSA private key used for signing.
     * @return A byte array containing the digital signature.
     *
     * @throws NoSuchAlgorithmException If the "SHA256withRSA" algorithm is not available.
     * @throws InvalidKeyException If the provided private key is invalid.
     * @throws SignatureException If an error occurs during the signing process.
     */
    private byte[] signWithPKCS1v15(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");   // Create Signature object with RSA & traditional padding (PKCS1v15)
        signature.initSign(privateKey);                                         // Initialize Signature object with private key
        signature.update(message);                                              // Update Signature object to sign message
        return signature.sign();                                                // Digital Signature
    }

    /**
     * Signs the given message using RSA with Probabilistic Signature Scheme (PSS) padding.
     * <p>
     * Creates a {@link Signature} instance with algorithm "RSASSA-PSS" and sets
     * specific PSS parameters: SHA-256 as hash function, MGF1 with SHA-256 as mask,
     * a salt length of 32 bytes, and default trailer field.
     * Uses the provided private key to generate the digital signature.
     * </p>
     *
     * @param message The data to sign; must not be {@code null}.
     * @param privateKey The RSA private key used for signing.
     * @return A byte array containing the digital signature.
     *
     * @throws NoSuchAlgorithmException If the "RSASSA-PSS" algorithm is not available.
     * @throws InvalidKeyException If the provided private key is invalid.
     * @throws SignatureException If an error occurs during the signing process.
     * @throws InvalidAlgorithmParameterException If the PSS parameters are invalid.
     */
    private byte[] signWithPSS(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("RSASSA-PSS");      // Create Signature object with RSA & PSS padding
        PSSParameterSpec pssSpecification = new PSSParameterSpec(               // Personalize Signature object
                "SHA-256",                  // principal hash
                "MGF1",                     // mask function
                MGF1ParameterSpec.SHA256,
                32,                  // salt length (size to SHA256)
                1);                         // default trailerField
        signature.setParameter(pssSpecification);                               // Set PSS Parameter Specification
        signature.initSign(privateKey);                                         // Initialize Signature object with private key
        signature.update(message);                                              // Update Signature object to sign message
        return signature.sign();                                                // Digital Signature
    }
}