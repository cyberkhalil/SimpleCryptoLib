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
     * @param msg the message to encrypt
     * @param key the key of the encryption
     * @return the encryptedMsg
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

    public static String encrypt(String msg, String key) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PublicKey keyFromString = getPublicFromString(key);
        return encrypt(msg, keyFromString);
    }

    /**
     * @param encryptedMsg the encrypted message to decrypt
     * @param privateKey the key of decryption
     * @return the origin msg
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

    public static String decrypt(String encryptedMsg, String privateKey) throws InvalidKeySpecException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        PrivateKey keyFromString = getPrivateFromString(privateKey);
        return decrypt(encryptedMsg, keyFromString);
    }

    private static PrivateKey getPrivateKey(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(TYPE);
        byte[] priv = privateKey.getEncoded();
        PKCS8EncodedKeySpec spec2 = new PKCS8EncodedKeySpec(priv);
        return keyFactory.generatePrivate(spec2);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        return kpg.genKeyPair();
    }

    public static String getPublicKey(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static String getPrivateKey(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public static PublicKey getPublicFromString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance(TYPE);

        return kf.generatePublic(X509publicKey);
    }

    public static PrivateKey getPrivateFromString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
        X509EncodedKeySpec privateKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance(TYPE);

        return kf.generatePrivate(privateKey);
    }

    public static PublicKey getPublicKey(PublicKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(TYPE);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key.getEncoded());
        return keyFactory.generatePublic(spec);
    }
}
