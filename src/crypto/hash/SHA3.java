package crypto.hash;

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SHA3 {

    private static final SHA3Size DEFAULT = SHA3Size.S512;

    public static String dohash(String string) {
        return dohash(string, DEFAULT, true);
    }

    public static String dohash(String string, SHA3Size s) {
        return dohash(string, s, true);
    }

    public static String dohash(String string, SHA3Size s, boolean bouncyEncoder) {
        SHA3Size SHA3Size = s == null ? DEFAULT : s;

        DigestSHA3 md = new DigestSHA3(SHA3Size.getValue());
        String text = string != null ? string : "null";
        md.update(text.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        return encode(digest, bouncyEncoder);
    }

    public static String encode(byte[] bytes, boolean bouncyEncoder) {
        if (bouncyEncoder) {
            return Hex.toHexString(bytes);
        } else {
            BigInteger bigInt = new BigInteger(1, bytes);
            return bigInt.toString(16);
        }
    }

    protected enum SHA3Size {

        S224(224),
        S256(256),
        S384(384),
        S512(512);

        int bits = 0;

        SHA3Size(int bits) {
            this.bits = bits;
        }

        public int getValue() {
            return this.bits;
        }
    }
}
