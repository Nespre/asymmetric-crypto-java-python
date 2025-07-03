import java.math.BigInteger;

public class ELGamalKeyPair {
    private final BigInteger primeP;
    private final BigInteger generatorG;
    private final BigInteger publicKeyY;
    private final BigInteger privateKeyX;

    public ELGamalKeyPair(BigInteger p, BigInteger g, BigInteger y, BigInteger x) {
        this.primeP = p;
        this.generatorG = g;
        this.publicKeyY = y;
        this.privateKeyX = x;
    }

    public BigInteger get_primeP() {return primeP; }
    public BigInteger get_generatorG(){
        return generatorG;
    }
    public BigInteger get_publicKeyY(){
        return publicKeyY;
    }
    public BigInteger get_privateKeyX(){
        return privateKeyX;
    }

}
