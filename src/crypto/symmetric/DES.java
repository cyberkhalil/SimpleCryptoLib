package crypto.symmetric;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static crypto.Util.UTF8;
import static crypto.Util.getRandom;
import java.util.Arrays;

/**
 *
 * @author khalil2535
 */
public class DES {

    private final static String TYPE = "DES";
    private final static String ALGORITHM = TYPE + "/ECB/PKCS5Padding";

    private DES() {
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
        SecretKeySpec secKey = getSecretKey(password);

        // init using the secret password and parameters
        cipher.init(Cipher.ENCRYPT_MODE, secKey);

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
        SecretKeySpec secKey = getSecretKey(password);

        // decode message
        byte[] decodedMsg = Base64.getDecoder().decode(encryptedMsg);

        // decrypt using the secret password and parameters
        cipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] decryptedMsg = cipher.doFinal(decodedMsg);

        // return as String
        return new String(decryptedMsg, UTF8);
    }

    private static SecretKeySpec getSecretKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, TYPE);
    }

    public static String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keygenerator = KeyGenerator.getInstance(TYPE);
        return Base64.getEncoder().encodeToString(keygenerator.generateKey().getEncoded());
    }
}
