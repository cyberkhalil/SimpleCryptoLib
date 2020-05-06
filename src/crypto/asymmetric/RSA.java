package crypto.asymmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static crypto.Util.UTF8;

public class RSA {

    public static final String TYPE = "RSA";
    public static final String ALGORITHM = TYPE + "/ECB/PKCS1Padding";

    /**
     *
     * @param msg
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encrypt(String msg, PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // get message bytes
        byte[] data = msg.getBytes(UTF8);

        // get real public key from encoded public key
        PublicKey pubKey = getPublicKey(key);

        // cipher object from RSA algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // init using public key
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        // encrypt message
        byte[] encrypted = cipher.doFinal(data);

        // return encoded message
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static PublicKey getPublicKey(PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(TYPE);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key.getEncoded());
        return keyFactory.generatePublic(spec);
    }

    /**
     *
     * @param encryptedMsg
     * @param privateKey
     * @return
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static String decrypt(String encryptedMsg, PrivateKey privateKey) throws InvalidKeySpecException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        // decode encrypted message
        byte[] encrypted = Base64.getDecoder().decode(encryptedMsg);

        // cipher object from RSA algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // get private key from encoded private key
        PrivateKey privKey = getPrivateKey(privateKey);

        // init using private key
        cipher.init(Cipher.DECRYPT_MODE, privKey);

        // decrypt the encrypted message
        byte[] decryptedMsg = cipher.doFinal(encrypted);

        // return plain message as String
        return new String(decryptedMsg, UTF8);
    }

    private static PrivateKey getPrivateKey(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(TYPE);
        byte[] priv = privateKey.getEncoded();
        PKCS8EncodedKeySpec spec2 = new PKCS8EncodedKeySpec(priv);
        return keyFactory.generatePrivate(spec2);
    }

    /**
     *
     * @return @throws NoSuchAlgorithmException
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        return kpg.genKeyPair();
    }

}
