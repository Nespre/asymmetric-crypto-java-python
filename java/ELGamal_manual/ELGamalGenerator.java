import java.math.BigInteger;
import java.security.SecureRandom;

public class ELGamalGenerator {
    private static SecureRandom random = new SecureRandom();
    private static int bitLength = 270; // For test, can be 256 or 512. Production: 2048 or more.

    public static ELGamalKeyPair generatorKeyPair() {
        // Generate a secure prime: p = 2q + 1 , q is also prime
        BigInteger q = BigInteger.probablePrime(bitLength - 1, random);
        BigInteger p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        // Check if p is prime
        while (!p.isProbablePrime(40)) {
            q = BigInteger.probablePrime(bitLength - 1, random);
            p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        }

        //Chose a good Generator for the group: g
        BigInteger g = BigInteger.TWO; // Starts with 2 (1 not secure)
        while (g.modPow(q, p).equals(BigInteger.ONE)) { // If true g is on a small group -> not secure
            g = g.add(BigInteger.ONE); // Testing until it finds g: g^q ≠ 1 mod p
        }

        // Create Private key: x ∈ [1, p−2]
        BigInteger x = new BigInteger(bitLength - 2, random);
        // Ensure x is >1 and <p-2
        while (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(p.subtract(BigInteger.TWO)) > 0) {
            x = new BigInteger(bitLength - 2, random);
        }

        // Create Public key: y = g^x mod p
        BigInteger y = g.modPow(x, p);

        return new ELGamalKeyPair(p, g, y, x);
    }

    public static SecureRandom get_random() {
        return random;
    }
    public static int get_bitLength() {
        return bitLength;
    }

}

