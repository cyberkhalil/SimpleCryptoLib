package crypto.symmetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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

    private AES() {
    }

    /**
     * @param msg the message to encrypt
     * @param password the password of the encryption to generate key from
     * @return the encryptedMsg
     */
    public static String encrypt(String msg, String password) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        // cipher algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // generate AES Key from String
        SecretKey secKey = new SecretKeySpec(Base64.getDecoder().decode(password), TYPE);

        // init using the secret password and parameters
        cipher.init(Cipher.ENCRYPT_MODE, secKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));

        // encrypt the message
        byte[] encryptedMsgBytes = cipher.doFinal(msg.getBytes(UTF8));

        // encode and encrypted message return message
        return Base64.getEncoder().encodeToString(encryptedMsgBytes);
    }

    /**
     * @param encryptedMsg the encrypted message to decrypt
     * @param password the password of decryption to generate the key from
     * @return the origin msg
     */
    public static String decrypt(String encryptedMsg, String password) throws NoSuchPaddingException,
            BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        // cipher object from AES algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // generate AES Key from String
        SecretKey secKey = new SecretKeySpec(Base64.getDecoder().decode(password), TYPE);

        // decode message
        byte[] decodedMsg = Base64.getDecoder().decode(encryptedMsg);

        // decrypt using the secret password and parameters
        cipher.init(Cipher.DECRYPT_MODE, secKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        byte[] decryptedMsg = cipher.doFinal(decodedMsg);

        // return as String
        return new String(decryptedMsg, UTF8);
    }

    public static String generateKey() {
        return getRandomString(16);
    }
}
