import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Represents a set of cryptographic parameters and utility methods for key generation and data conversion.
 * <p>
 *     This class provides methods for generating RSA and ECDSA key pairs, converting between
 *     strings, bytes, hexadecimal, and Base64 representations, and storing a predefined message.
 */
public class CryptoUtils {
    private final String message = "ESTAMOS NA AULA DE CRIPTOGRAFIA";


    /**
     * Generates a new RSA key pair with a 2048-bit key size and a standard public exponent (65537).
     * <p>
     * This method uses the {@code KeyPairGenerator} with an {@code RSAKeyGenParameterSpec}
     * to produce a secure key pair suitable for cryptographic operations.
     *
     * @return a {@code KeyPair} containing the generated RSA public and private keys.
     * @throws NoSuchAlgorithmException if the RSA algorithm is not supported.
     * @throws InvalidAlgorithmParameterException if the RSA key generation parameters are invalid.
     *
     * <p><b>Example usage:</b>
     * <pre>{@code
     *     CryptoUtils crypto = new CryptoUtils();
     *     KeyPair pair = crypto.generateRSAKeyPair();
     * }</pre>
     * @since 1.0
     */
    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");                           // Get a KeyPairGenerator instance for RSA algorithm
        RSAKeyGenParameterSpec rsaSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);   // Set key size to 2048 bits & public exponent t0 65537 - standard
        keyGenerator.initialize(rsaSpec, new SecureRandom());                                                  // Initialize generator with the RSA spec and a secure random seed
        return keyGenerator.generateKeyPair();                                                                 // Return the generated RSA key pair
    }

    /**
     * Generates a new ECDSA (Elliptic Curve Digital Signature Algorithm) key pair using the secp256k1 curve.
     * <p>
     * This method uses the Bouncy Castle provider to generate a key pair suitable for elliptic curve
     * cryptography with the secp256k1 curve — commonly used in Bitcoin and blockchain technologies.
     * <p>
     * <b>Note:</b> Ensure that the Bouncy Castle provider is correctly added to the classpath.
     *
     * @return a {@code KeyPair} containing the generated ECDSA public and private keys.
     * @throws NoSuchAlgorithmException if the EC algorithm is not supported.
     * @throws NoSuchProviderException if the Bouncy Castle provider is not available.
     * @throws InvalidAlgorithmParameterException if the secp256k1 curve is not supported.
     *
     * <p><b>Example usage:</b>
     * <pre>{@code
     *     CryptoUtils crypto = new CryptoUtils();
     *     KeyPair pair = crypto.generateECDSAKeyPair();
     * }</pre>
     * @since 1.0
     */
    public KeyPair generateECDSAKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC", "BC");               // Get a KeyPairGenerator instance for EC algorithm & BC provider
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");                               // Define the curve parameter spec using secp256k1 curve (Bitcoin curve)
        keyGenerator.initialize(ecSpec, new SecureRandom());                                                   // Initialize generator with the curve spec and a secure random seed
        return keyGenerator.generateKeyPair();                                                                 // Return the generated EC key pair
    }

    /**
     * Converts a string into its UTF-8 encoded byte array.
     *
     * @param message the input string to convert
     * @return the UTF-8 encoded byte array of the input string
     * @since 1.7
     */
    public byte[] stringToBytes(String message) {
        return message.getBytes(StandardCharsets.UTF_8);
    }
    /**
     * Converts a UTF-8 encoded byte array into a string.
     *
     * @param bytes the UTF-8 encoded byte array to convert
     * @return the resulting string
     * @since 1.7
     */
    public String bytesToString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param bytes the input byte array
     * @return a hexadecimal string representing the input bytes
     * @since 9.0
     */
    public String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
    /**
     * Converts a byte array to its Base64 encoded representation.
     *
     * @param bytes the input byte array to be converted
     * @return a Base64 encoded string representation of the input bytes
     * @since 1.8
     */
    public String bytesToB64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Returns the internal message string.
     *
     * @return the current message
     */
    public String getMessage() {
        return message;
    }
}