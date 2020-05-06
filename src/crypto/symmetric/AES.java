package crypto.symmetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import static crypto.Util.UTF8;
import static crypto.Util.getRandomString;

/**
 *
 * @author khalil2535
 */
public class AES {

    private final static String TYPE = "AES";
    private final static String ALGORITHM = TYPE + "/CBC/PKCS5Padding";
    private final static String KEY_HASH = "PBKDF2WithHmacSHA256";

    private AES() {
    }

    /**
     *
     * @param msg
     * @param password
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    public static String encrypt(String msg, String password) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        // cipher algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // generate AES Key from String
        SecretKey secKey = getSecretKey(password);

        // init using the secret password and parameters
        cipher.init(Cipher.ENCRYPT_MODE, secKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));

        // encrypt the message
        byte[] encryptedMsgBytes = cipher.doFinal(msg.getBytes(UTF8));

        // encode and encrypted message return message
        return Base64.getEncoder().encodeToString(encryptedMsgBytes);
    }

    /**
     *
     * @param encryptedMsg
     * @param password
     * @return
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    public static String decrypt(String encryptedMsg, String password) throws NoSuchPaddingException,
            BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        // cipher object from AES algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // generate AES Key from String
        SecretKey secKey = getSecretKey(password);

        // decode message
        byte[] decodedMsg = Base64.getDecoder().decode(encryptedMsg);

        // decrypt using the secret password and parameters
        cipher.init(Cipher.DECRYPT_MODE, secKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        byte[] decryptedMsg = cipher.doFinal(decodedMsg);

        // return as String
        return new String(decryptedMsg, UTF8);
    }

    private static SecretKeySpec getSecretKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_HASH);
        byte[] salt = new byte[8];
        KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), TYPE);
    }

    /**
     *
     * @return SecureRandom Key for AES
     */
    public static String generateKey() {
        return getRandomString(16);
    }
}
