import java.math.BigInteger;

public class ELGamalEncryptor {

    public static BigInteger[] encrypt (BigInteger plaintext, BigInteger p, BigInteger g, BigInteger y) {
        // random k ∈ [1, p−2]
        BigInteger k = new BigInteger(ELGamalGenerator.get_bitLength() -2, ELGamalGenerator.get_random());
        // Ensure k is >1 and <p-2
        while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(p.subtract(BigInteger.TWO)) > 0) {
            k = new BigInteger(ELGamalGenerator.get_bitLength() -2, ELGamalGenerator.get_random());
        }
        BigInteger a = g.modPow(k, p);                      // a = g^k mod p
        BigInteger b = plaintext.multiply(y.modPow(k, p));    // b = m × y^k mod p
        b = b.mod(p);                                       // ensure b is in the group

        return new BigInteger[] {a, b};
    }

    public static BigInteger decrypt(BigInteger[] ciphertext, BigInteger p, BigInteger x) {
        BigInteger a = ciphertext[0];
        BigInteger b = ciphertext[1];

        // Calculate s: s = a^x mod p
        BigInteger s = a.modPow(x, p);
        // Modular Inverse of s: s^-1 = s^-1 mod p
        BigInteger s_1 = s.modInverse(p);

        // Get original Message: m = b × s⁻¹ mod p
        return b.multiply(s_1).mod(p);
    }

    public static BigInteger stringToBigInt(String text) {
        return new BigInteger(text.getBytes());
    }

    public static String bigIntToString(BigInteger bigInt) {
        return new String(bigInt.toByteArray());
    }
}
