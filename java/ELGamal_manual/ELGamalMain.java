import java.math.BigInteger;

public class ELGamalMain {
    public static void main(String[] args) {
        ELGamalKeyPair keyPair = ELGamalGenerator.generatorKeyPair();

        String message = "This an lesson about Cryptography";
        BigInteger plaintext = ELGamalEncryptor.stringToBigInt(message);

        if (plaintext.compareTo(keyPair.get_primeP()) >= 0) {
            throw new IllegalArgumentException("Message too large for the modulus.");
        }

        BigInteger[] ciphertext = ELGamalEncryptor.encrypt(plaintext, keyPair.get_primeP(), keyPair.get_generatorG(), keyPair.get_publicKeyY());
        BigInteger a = ciphertext[0];
        BigInteger b = ciphertext[1];

        BigInteger decrypted = ELGamalEncryptor.decrypt(ciphertext, keyPair.get_primeP(), keyPair.get_privateKeyX());
        String result = ELGamalEncryptor.bigIntToString(decrypted);

        System.out.println("Original: \t" + message);
        System.out.println("Cipher: \t" + a + "\n\t\t\t" + b);
        System.out.println("Decrypted: \t" + result);
        System.out.println();
        System.out.println("Public Key: \t" + keyPair.get_publicKeyY());
        System.out.println("Private Key: \t" + keyPair.get_privateKeyX());
    }
}
