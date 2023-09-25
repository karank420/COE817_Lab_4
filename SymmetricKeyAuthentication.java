import java.security.Key;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricKeyAuthentication {
    private static final String ALGORITHM = "AES";
    private static final byte[] KEY = "MZygpewJsCpRrfOr".getBytes();

    public static void main(String[] args) throws Exception {
        // Alice
        String identityA = "Alice";
        int nonceA = 12345;

        // Bob
        String identityB = "Bob";
        int nonceB = 56789;

        // (1) Alice sends its identity and nonce to Bob

        String message1 = identityA + " " + nonceA;
        System.out.println("Message 1: " + message1);

        // (2) Bob receives message 1 and responds with a nonce and encrypted message
        // that includes Bob's identity and nonceA
        String message2 = nonceB + " " + encrypt(identityB + " " + nonceA, KEY);
        System.out.println("Message 2: " + message2);

        // (3) Alice receives message 2 and decrypts it
        String decryptedMessage2 = decrypt(message2.split(" ")[1], KEY);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);

        // (4) Alice sends an encrypted message that includes Alice's identity and nonceB
        String message3 = encrypt(identityA + " " + nonceB, KEY);
        System.out.println("Message 3: " + message3);

        // (5) Bob receives message 3 and decrypts it
        String decryptedMessage3 = decrypt(message3, KEY);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }

    public static String encrypt(String data, byte[] key) throws Exception {
        Key secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String data, byte[] key) throws Exception {
        Key secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(data.getBytes());
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData);
    }
}

