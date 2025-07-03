import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAGenerator {
    private static final SecureRandom random = new SecureRandom();
    private static final int BIT_LENGTH = 256; // For test, can be 256 or 512. Production: 2048 or more.

    public static RSAKeyPair generateKeyPair() {
        // Select 2 Prime numbers: p & q
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, random);
        BigInteger q;
        do {
            q = BigInteger.probablePrime(BIT_LENGTH, random);
        } while (q.equals(p));

        // Calculate n = p * q
        BigInteger n = p.multiply(q);

        // Calculate φ(n) = (p - 1) × (q - 1)
        BigInteger phiN = phi(p).multiply(phi(q));

        // Chose e: 1 < e < φ(n) e mdc(e, φ(n)) = 1
        // public key (e, n)
        BigInteger e = BigInteger.valueOf(65537); // Common value and secure
        // Ensures that is coprime with φ(n)
        if (!phiN.gcd(e).equals(BigInteger.ONE)){
            e = BigInteger.valueOf(3);
            while (!phiN.gcd(e).equals(BigInteger.ONE)) {
                e = e.add(BigInteger.TWO);}
        }

        // Calculate the d: modular inverse of e in respect to φ(n)
        // private key (d, n)
        BigInteger d = e.modInverse(phiN);

        return new RSAKeyPair(e, d, n);
    }

    private static BigInteger phi(BigInteger number){
        // Methods excepts prime to be a prime number.
        if (!number.isProbablePrime(40)) {
            throw new IllegalArgumentException("Error: number is not prime → " + number);
        }
        return number.subtract(BigInteger.ONE);
    }
}