import java.math.BigInteger;

public class RSAEncryptor {

    public static BigInteger encrypt(BigInteger plaintext, BigInteger e, BigInteger n) {
        return plaintext.modPow(e, n);
    }

    public static BigInteger decrypt(BigInteger cipher, BigInteger d, BigInteger n) {
        return cipher.modPow(d, n);
    }

    public static BigInteger stringToBigInt(String text) {
        return new BigInteger(text.getBytes());
    }

    public static String bigIntToString(BigInteger bigInt) {
        return new String(bigInt.toByteArray());
    }
}
