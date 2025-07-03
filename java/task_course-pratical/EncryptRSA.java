import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyPair;
import java.security.*;
import java.util.Base64;

/**
 * Represents a class for encrypting and decrypting messages using RSA encryption.
 * <p>
 * This class provides methods for encrypting and decrypting byte arrays using RSA encryption
 * with OAEP padding and SHA-256 hashing. It requires a KeyPair containing a public key for
 * encryption and a private key for decryption.
 */
public class RSAEncrypt {
    private final String ALGORITHM = "RSA";
    private final String MODE = "ECB";
    private final String HASHINGALGORITHM = "SHA-256";
    private final String PADDINGSCHEME = "OAEPWith" + HASHINGALGORITHM + "AndMGF1Padding";
    private final String TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDINGSCHEME;     // "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    /**
     * Encrypts a byte array message using RSA with OAEP padding and SHA-256.
     * <p>
     * Uses the public key from the given {@code KeyPair} to encrypt the input.
     * The result is a ciphertext represented as a byte array.
     * If the encryption fails, it throws an exception.
     *
     * @param message the plaintext message to encrypt; must not be {@code null}
     * @param keyPair the key pair containing the public key to be used for encryption; must not be {@code null}
     * @return a byte array containing the encrypted (ciphertext) representation of the input message
     *
     * @throws NoSuchAlgorithmException if the RSA or OAEP algorithm is not available in the environment
     * @throws InvalidKeyException if the provided public key is invalid or unsupported
     * @throws NoSuchPaddingException if the OAEP padding scheme is not supported
     * @throws IllegalBlockSizeException if the message is too large for the encryption block size
     * @throws BadPaddingException if the padding is invalid or the input is not padded correctly
     *
     * @since 1.0
     *
     * <p><b>Example usage:</b></p>
     * <pre>{@code
     * CryptoUtils cryptoUtils = new CryptoUtils();
     * byte[] messageBytes = cryptoUtils.stringToBytes(message);
     * KeyPair rsaKeyPair = cryptoUtils.generateRSAKeyPair();
     *
     * RSAEncrypt rsaEncryptor = new RSAEncrypt();
     * byte[] cipherBytes = rsaEncryptor.encryptMessage(messageBytes, rsaKeyPair);
     * }</pre>
     */
    public byte[] encryptMessage(byte[] message, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance(TRANSFORMATION);      // Creates the cipher object with default secure mode OAEP
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());   // Initializes the cipher with public key and encryption mode

        return encryptCipher.doFinal(message);                          // Encrypts bytes of the message
    }

    /**
     * Decrypts a byte array message using RSA with OAEP padding and SHA-256.
     * <p>
     * Uses the private key from the given {@code KeyPair} to decrypt the input.
     * The result is a plaintext message represented as a byte array.
     * If the decryption fails, it throws an exception.
     *
     * @param cipherMessage the ciphertext message to decrypt; must not be {@code null}
     * @param keyPair the key pair containing the private key to be used for decryption; must not be {@code null}
     * @return a byte array containing the decrypted (plaintext) representation of the input message
     *
     * @throws NoSuchAlgorithmException if the RSA or OAEP algorithm is not available in the environment
     * @throws InvalidKeyException if the provided private key is invalid or unsupported
     * @throws NoSuchPaddingException if the OAEP padding scheme is not supported
     * @throws IllegalBlockSizeException if the message is too large for the decryption block size
     * @throws BadPaddingException if the padding is invalid or the input is not padded correctly
     *
     * @since 1.0
     *
     * <p><b>Example usage:</b></p>
     * <pre>{@code
     * CryptoUtils cryptoUtils = new CryptoUtils();
     * KeyPair rsaKeyPair = cryptoUtils.generateRSAKeyPair(); - same key pair as in encryptMessage()
     *
     * RSAEncrypt rsaEncryptor = new RSAEncrypt();
     * byte[] decryptedBytes = rsaEncryptor.decryptMessage(cipherBytes, rsaKeyPair);
     * }</pre>
     */
    public byte[] decryptMessage(byte[] cipherMessage, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance(TRANSFORMATION);      // Creates the cipher object with default secure mode OAEP
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());  // Initializes the cipher with private key and decryption mode

        return decryptCipher.doFinal(cipherMessage);                    // Decrypts bytes of message
    }
}