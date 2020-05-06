
import crypto.symmetric.DES;

/**
 *
 * @author khalil2535
 */
public class Main {

    public static void main(String[] args) throws Exception {
        String message = "Test my message !!";
        String key = DES.generateKey();
        System.out.println("origin:" + message);

        String encrypted = DES.encrypt(message, key);
        System.out.println("encrypted:" + encrypted);

        String plain = DES.decrypt(encrypted, key);
        System.out.println("plain:" + plain);
    }
}
