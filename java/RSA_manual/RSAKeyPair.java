import java.math.BigInteger;

public class RSAKeyPair {
    private final BigInteger publicKeyE;
    private final BigInteger privateKeyD;
    private final BigInteger modulusN;

    public RSAKeyPair(BigInteger e, BigInteger d, BigInteger n) {
        this.publicKeyE = e;
        this.privateKeyD = d;
        this.modulusN = n;
    }

    public BigInteger get_publicKeyE(){
        return publicKeyE;
    }
    public BigInteger get_privateKeyD(){
        return privateKeyD;
    }
    public BigInteger get_modulusN(){
        return modulusN;
    }
}
