import java.math.BigInteger;

public class RSAMain {
    public static void main(String[] args) {

        RSAKeyPair keyPair = RSAGenerator.generateKeyPair();

        String message = "This an lesson about Cryptography";
        BigInteger plaintext = RSAEncryptor.stringToBigInt(message);

        if (plaintext.compareTo(keyPair.get_modulusN()) >= 0) {
            throw new IllegalArgumentException("Message is too large for the current modulus n.");
        }

        BigInteger ciphertext = RSAEncryptor.encrypt(plaintext, keyPair.get_publicKeyE(), keyPair.get_modulusN());
        BigInteger decrypted = RSAEncryptor.decrypt(ciphertext, keyPair.get_privateKeyD(), keyPair.get_modulusN());

        String result = RSAEncryptor.bigIntToString(decrypted);

        System.out.println("Original: \t" + message);
        System.out.println("Cipher: \t" + ciphertext);
        System.out.println("Decrypted: \t" + result);
        System.out.println();
        System.out.println("Exponent of Public Key: \t" + keyPair.get_publicKeyE());
        System.out.println("Exponent of Private Key: \t" + keyPair.get_privateKeyD());


    }
}
