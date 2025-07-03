import java.security.KeyPair;
import java.util.Scanner;

/**
 * Entry point for executing cryptographic operations via command-line.
 * <p>
 * This class demonstrates the usage of RSA and ECDSA for encryption, decryption,
 * digital signature generation, and signature verification. It uses the {@code CryptoUtils},
 * {@code RSAEncrypt}, {@code RSASignature}, and {@code ECDSASignature} utility classes.
 * <p>
 * The program prints results to the console in both hexadecimal and Base64 formats,
 * and allows the user to repeat the operations in a loop.
 *
 * <p><b>Operations demonstrated:</b></p>
 * <ul>
 *   <li>RSA encryption and decryption</li>
 *   <li>RSA signature (PSS and PKCS#1 v1.5)</li>
 *   <li>ECDSA signature and verification</li>
 * </ul>
 *
 * @author Lucas Marques
 * @version 1.0
 * @since 1.0
 */
public class Main {
    public static void main(String[] args) throws Exception {
        // Bases
        CryptoUtils cryptoUtils = new CryptoUtils();
        String message = cryptoUtils.getMessage();
        byte[] messageBytes = cryptoUtils.stringToBytes(message);
        KeyPair rsaKeyPair = cryptoUtils.generateRSAKeyPair();
        KeyPair ecKeyPair = cryptoUtils.generateECDSAKeyPair();
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {
        // Encryption RSA
            System.out.println("\n------ ENCRYPT MESSAGE - RSA ------");
            RSAEncrypt rsaEncryptor = new RSAEncrypt();

            byte[] cipherBytes = rsaEncryptor.encryptMessage(messageBytes, rsaKeyPair);
            String encryptedMessageHex = cryptoUtils.bytesToHex(cipherBytes);
            String encryptedMessageB64 = cryptoUtils.bytesToB64(cipherBytes);

            byte[] decryptedBytes = rsaEncryptor.decryptMessage(cipherBytes, rsaKeyPair);
            String decryptedMessage = cryptoUtils.bytesToString(decryptedBytes);

            System.out.println("Original Message \t\t" + message);
            System.out.println("Encrypted Msg (Hex) \t" + encryptedMessageHex);
            System.out.println("Encrypted Msg (B64) \t" + encryptedMessageB64);
            System.out.println("Decrypted Message \t\t" + decryptedMessage);


        // Signature RSA
            System.out.println("\n------ SIGNATURE MESSAGE - RSA ------");
            RSASignature rsaSigner = new RSASignature();

            byte[] pssSign = rsaSigner.defaultSignature(messageBytes, rsaKeyPair.getPrivate());
            String defaultSignHex = cryptoUtils.bytesToHex(pssSign);
            byte[] pkcs1Sign = rsaSigner.modernSignature(messageBytes, rsaKeyPair.getPrivate());
            String modernSignHex = cryptoUtils.bytesToHex(pkcs1Sign);

            System.out.println("Default Signature - PSS \t" + defaultSignHex);
            System.out.println("Modern Signature - PKCS1\t" + modernSignHex);
            System.out.println("Same Private Key - RSA 2048 bits \n\t" + cryptoUtils.bytesToHex(rsaKeyPair.getPrivate().getEncoded()));


        // Signature ECDSA
            System.out.println("\n------ SIGNATURE MESSAGE - ECC ------");
            ECDSASignature ecSigner = new ECDSASignature();

            byte[] ecdsaSign = ecSigner.signature(messageBytes, ecKeyPair.getPrivate());
            String ecdsaSignHex = cryptoUtils.bytesToHex(ecdsaSign);

            boolean ecIsValid = ecSigner.verifySignature(messageBytes, ecdsaSign, ecKeyPair.getPublic());

            System.out.println("ECDSA Signature (Hex) \t" + ecdsaSignHex);
            System.out.println("ECDSA Signature Valid? \t" + ecIsValid);
            System.out.println("ECDSA Public Key \t\t" + cryptoUtils.bytesToHex(ecKeyPair.getPublic().getEncoded()));
            System.out.println("ECDSA Private Key \t\t" + cryptoUtils.bytesToHex(ecKeyPair.getPrivate().getEncoded()));


        // Repeat??
            System.out.println("\nPress Enter to exit or type 'continue' to continue");
            String choice = scanner.nextLine();
            if (!choice.equals("continue")) {
                running = false;
                scanner.close();
            }
        }
    }
}