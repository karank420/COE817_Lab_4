import javax.crypto.Cipher;
import java.security.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAProtocol {
    private PrivateKey privateKeyKDC;
    private PublicKey publicKeyKDC;

    private PrivateKey privateKeyA;
    private PublicKey publicKeyA;
    private PrivateKey privateKeyB;
    private PublicKey publicKeyB;

    private PrivateKey privateKeyC;

    private PublicKey publicKeyC;

    private static final String PRIVATE_KEY_STRING_KDC = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJhBgzcXBm5A0srvFFu4FsBy+LLW+X0sH/9RvP40VIGOCusY0/CqA65YXWqyQE5jQCegBmnAeVYSvK+3PU4Y1fmr1uiquE6sZB5sl96T0ka+PKzPf4oKoAi6nwLUSenj5xTFjLsFGiuMXrCpMCPImf9JBVk89TJV43Xs3DSNKoj1AgMBAAECgYBsDysCgVv2ChnRH4eSZP/4zGCIBR0C4rs+6RM6U4eaf2ZuXqulBfUg2uRKIoKTX8ubk+6ZRZqYJSo3h9SBxgyuUrTehhOqmkMDo/oa9v7aUqAKw/uoaZKHlj+3p4L3EK0ZBpz8jjs/PXJc77Lk9ZKOUY+T0AW2Fz4syMaQOiETzQJBANF5q1lntAXN2TUWkzgir+H66HyyOpMu4meaSiktU8HWmKHa0tSB/v7LTfctnMjAbrcXywmb4ddixOgJLlAjEncCQQC6Enf3gfhEEgZTEz7WG9ev/M6hym4C+FhYKbDwk+PVLMVR7sBAtfPkiHVTVAqC082E1buZMzSKWHKAQzFL7o7zAkBye0VLOmLnnSWtXuYcktB+92qh46IhmEkCCA+py2zwDgEiy/3XSCh9Rc0ZXqNGD+0yQV2kpb3awc8NZR8bit9nAkBo4TgVnoCdfbtq4BIvBQqR++FMeJmBuxGwv+8n63QkGFQwVm6vCuAqFHBtQ5WZIGFbWk2fkKkwwaHogfcrYY/ZAkEAm5ibtJx/jZdPEF9VknswFTDJl9xjIfbwtUb6GDMc0KH7v+QTBW4GsHwt/gL+kGvLOLcEdLL5rau3IC7EQT0ZYg==";
    private static final String PUBLIC_KEY_STRING_KDC =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYQYM3FwZuQNLK7xRbuBbAcviy1vl9LB//Ubz+NFSBjgrrGNPwqgOuWF1qskBOY0AnoAZpwHlWEryvtz1OGNX5q9boqrhOrGQebJfek9JGvjysz3+KCqAIup8C1Enp4+cUxYy7BRorjF6wqTAjyJn/SQVZPPUyVeN17Nw0jSqI9QIDAQAB";
    private static final String PUBLIC_KEY_STRING_A = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCbMZz3kmac/Wn0LwPN5Hj4VtGhDwY3I/t4/lwYZLxnmDdGh2+3KkH/SmPH1OGRe+qAH8mlBsf1PtXvN1iceN7Xe/txcAQbSN8Ljfol1Q7dgi+OIxfe4l0VKFmUsKKhv9+WCtDj2Kx8yWa3uVgaeH2JwIUsupDBndpJEhegUfhIhwIDAQAB";
    private static final String PRIVATE_KEY_STRING_A = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJsxnPeSZpz9afQvA83kePhW0aEPBjcj+3j+XBhkvGeYN0aHb7cqQf9KY8fU4ZF76oAfyaUGx/U+1e83WJx43td7+3FwBBtI3wuN+iXVDt2CL44jF97iXRUoWZSwoqG/35YK0OPYrHzJZre5WBp4fYnAhSy6kMGd2kkSF6BR+EiHAgMBAAECgYAgND3l09/uQNndPWpVLc16fw2WFdeM1q8mzuWOfEzqVFhYDt+8Sw0R7D5jZ8X9GhEx0CbYU11oA0eCkeIV6jEXhEmQz5bDyJaFfrpPEWYRdTylZkXh3Mp6FGJWXw03C8BpLOTDh/Sxs4af1k/EUO6qu+N6euzAywkVR4YbZ9h/IQJBAL7A2UIBRmKteJSNBm3jB8PzrUkZkZtAPIXxIHlvMRpSEDIX/UFXf/0zAAPn1kQ3dSmAQw30M7EBJmuIQhe576ECQQDQRwan+y6XCDTR/kLh/L+0H5LToB8qIsTVfTZXrjWzA1EYakhlzRx+VsLwR/YbsIwOiiJf6GlypMd+CJtXW2cnAkAJXQwNGmTrGRrPJ/EF2dwauU5rRS8JkOinpoNykou1gAu9ecH7wCDPO/6nMm0pIhPFOr+P4snayXSqWKDt6zmhAkAuT1yfhS46zsxP1OUyMmy9tDeFbpj/WXPCtHCc1lOCVj5120v1tsGbJdd6bcW/KmY55WT3RkoL/6+LyoYfymcJAkEAhFP2AhTIJ1/Qp5WybN2FguoOIcQ873EbswYQ60DattxgTp8vwwauH+uOzg7ss2WnrXTH3Vm4BSnJb3jutj6ddw==";
    private static final String PUBLIC_KEY_STRING_B = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDBOAhDBIHXzKE8i8HuVAqJ3ZIS8u0rHOcbv//LyLdUCopKfBPw1fDjRAHbLNFZtFsAIWMTp2yDWCrURmAibCZ4yxZPh3mZaLVz+LOQYVQJTb5gUMUJcFuZFOHrLjjKr9LcL6DzVEtEbqUi3boM/dZsGNwwMNRhte0/0Z/F/5pTQIDAQAB";
    private static final String PRIVATE_KEY_STRING_B = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIME4CEMEgdfMoTyLwe5UCondkhLy7Ssc5xu//8vIt1QKikp8E/DV8ONEAdss0Vm0WwAhYxOnbINYKtRGYCJsJnjLFk+HeZlotXP4s5BhVAlNvmBQxQlwW5kU4esuOMqv0twvoPNUS0RupSLdugz91mwY3DAw1GG17T/Rn8X/mlNAgMBAAECgYATWrjGQPt30dELcSBP7ojgVUiEmQfMVo5UjVQtTPgEQ/eacZrRmZyBI3k684yPA8eLgg84YROsDgxZ+ma/RXfMJtzEfBRqh0Z+6W3tdi1zChG3NYKWDci5uH58UlwxJzTLWcfO8X9xT7qpoKdx1ocs/aeYaexV3gssPNBtdWN/KQJBAP0BI9qxZj0boXJ1MfbQhIaNQTl1hQ3NUuPIa73SoxpKq6CPxApLtAIDR20A9Xro9fefdbikMNMUnRWV3oVxteUCQQCEkf76x2ASSf9hzVYpnYbLjLKzoREwdW0Xpv3K24A5Vm5+yztmilwl73F4NLa7OWKYhdaKQps8KqLgh50esq9JAkAKFWWMbc2ZWeSRX0Jih+UAR9j1pU1sQ2auVWqV4jNF9PvqJlC16FaATgkmuwcNowNKnzxd441enE+2cIax4tpRAkBwHxpL9zvlu/fmO8hXwgczOHgbPGpRVb9CddXIMAUueU9SpYhDnVl6LB0H0W2Kw2oEHY3puZOZO2YuCAR25iEhAkEA4o1/nUfDoJRdjg55cM1+ghbVhgsOCHTAGKn8zV+tN6DoKDtcrOBb8He723U8i3dEjCT1bb/l7F6N7K+6rXs/Cw==";

    private static final String PUBLIC_KEY_STRING_C = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDv5ODW7IEJCkW7wl8eSbOMpivLn/aGxQqAmo6DxdFbvqVvuagh/zewlFddlgTy6NDqfygdMfPRy/2vJPsys2+VkHrS+UEomyiSiKdAlUJdnVQalORUwfYBR3+jHaJktBp9LIYFmZzed1kn82uwrnCASbNMUgf9+oyMsU7NoVdkrQIDAQAB";

    private static final String PRIVATE_KEY_STRING_C = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAO/k4NbsgQkKRbvCXx5Js4ymK8uf9obFCoCajoPF0Vu+pW+5qCH/N7CUV12WBPLo0Op/KB0x89HL/a8k+zKzb5WQetL5QSibKJKIp0CVQl2dVBqU5FTB9gFHf6MdomS0Gn0shgWZnN53WSfza7CucIBJs0xSB/36jIyxTs2hV2StAgMBAAECgYAKzCCxk8IIC+IRHiHFXXhbIYSRnPDN5pL/MFWvSSlP6ZANLAxNAW16gWbAQ9cTrtZuY4xE6iFpBTc1GaNDyC9CtAfnP3U0PoRnd+YrBYPA5ee9+fiR1g6hR14JPRNBC3oKZwc6oTwMl9/YNjRMiPxW5RGCYLOGva6ZhgqXA/2R4QJBAPfv+p1/WN6Bdo6Zm+/+Yc43G70lvdY6EW8x7PirEGEF4Dg0W6enuTEG6dVPj3QSVTkmNJJ7uW6sTq7GfA8Ptc0CQQD3sfCxSjOQ8VA9WEPiRlAQwWbs34Uu/zuWqk3WpDhslqb46ETc9hfwFQHGUuo+05n2+p9mVtVrUqy85dOi74phAkEArk82N6I/XXdRXaHbAtgp9OvDgbBWDZWXikBkZNMHWd7iq0EMKwt85F4C6Wfc5/K3nc0hata3IHrdenyq3X/jBQJBALEJs9lkCbtdX1aZUdvXGb8AHQrNMCpJL1Qe4Ye61MF4ZFuf2Ch+lNl6ikwwU1EYeQF4XJoPEnelHeXd9wiMYcECQEIuj2U4FDqbo4+cG5Q0mUpo97r4tTnm4IaXsKkS0dNf/E5YZI8gaRefy94j+LpqQ6YDAOy4OFKQ8baPmbdTJLk=";

    public void init(){
        try {
            //KDC key pair generation
            KeyPairGenerator generatorKDC = KeyPairGenerator.getInstance("RSA");
            generatorKDC.initialize(1024);
            KeyPair pairKDC = generatorKDC.generateKeyPair();
            privateKeyKDC = pairKDC.getPrivate();
            publicKeyKDC = pairKDC.getPublic();

            //Alice Key pair generation
            KeyPairGenerator generatorA = KeyPairGenerator.getInstance("RSA");
            generatorA.initialize(1024);
            KeyPair pairA = generatorA.generateKeyPair();
            privateKeyA = pairA.getPrivate();
            publicKeyA = pairA.getPublic();

            //Bob Key pair generation
            KeyPairGenerator generatorB = KeyPairGenerator.getInstance("RSA");
            generatorB.initialize(1024);
            KeyPair pairB = generatorB.generateKeyPair();
            privateKeyB = pairB.getPrivate();
            publicKeyB = pairB.getPublic();

            //C Key pair generation
            KeyPairGenerator generatorC = KeyPairGenerator.getInstance("RSA");
            generatorC.initialize(1024);
            KeyPair pairC = generatorC.generateKeyPair();
            privateKeyC = pairC.getPrivate();
            publicKeyC = pairC.getPublic();

        } catch (Exception ignored) {
        }
    }

    public void initFromStrings(){
        try{
            X509EncodedKeySpec keySpecPublicKDC = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING_KDC));
            PKCS8EncodedKeySpec keySpecPrivateKDC = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING_KDC));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKeyKDC = keyFactory.generatePublic(keySpecPublicKDC);
            privateKeyKDC = keyFactory.generatePrivate(keySpecPrivateKDC);

            X509EncodedKeySpec keySpecPublicA = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING_A));
            PKCS8EncodedKeySpec keySpecPrivateA = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING_A));

            publicKeyA = keyFactory.generatePublic(keySpecPublicA);
            privateKeyA = keyFactory.generatePrivate(keySpecPrivateA);

            X509EncodedKeySpec keySpecPublicB = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING_B));
            PKCS8EncodedKeySpec keySpecPrivateB = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING_B));

            publicKeyB = keyFactory.generatePublic(keySpecPublicB);
            privateKeyB = keyFactory.generatePrivate(keySpecPrivateB);

            X509EncodedKeySpec keySpecPublicC = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING_C));
            PKCS8EncodedKeySpec keySpecPrivateC = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING_C));

            publicKeyC = keyFactory.generatePublic(keySpecPublicC);
            privateKeyC = keyFactory.generatePrivate(keySpecPrivateC);
        }catch (Exception ignored){}
    }


    public void printKeys(){
        System.err.println("KDC Public key\n"+ encode(publicKeyKDC.getEncoded()));
        System.err.println("KDC Private key\n"+ encode(privateKeyKDC.getEncoded()));

        System.err.println("Alice Public key\n"+ encode(publicKeyA.getEncoded()));
        System.err.println("Alice Private key\n"+ encode(privateKeyA.getEncoded()));

        System.err.println("Bob Public key\n"+ encode(publicKeyB.getEncoded()));
        System.err.println("Bob Private key\n"+ encode(privateKeyB.getEncoded()));

        System.err.println("C Public key\n"+ encode(publicKeyC.getEncoded()));
        System.err.println("C Private key\n"+ encode(privateKeyC.getEncoded()));

    }

    public String encryptKDCPub(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyKDC);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encryptKDCPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyKDC);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encryptAPub(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyA);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encryptAPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyA);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encryptBPub(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyB);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encryptBPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyB);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public String decryptKDCPriv(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyKDC);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decryptKDCPub(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKeyKDC);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decryptAPriv(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyA);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decryptAPub(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKeyA);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decryptBPriv(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decryptBPub(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKeyB);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String encryptCPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyC);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encryptCPub(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyC);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String decryptCPriv(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyC);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decryptCPub(String encryptedMessage) throws Exception {
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKeyC);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    //create digital signature for Alice
    public String signAPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKeyA);
        signature.update(messageToBytes);
        byte[] signatureBytes = signature.sign();
        return encode(signatureBytes);
    }

    //verify digital signature for Alice
    public boolean verifyAPub(String message, String signature) throws Exception {
        byte[] messageToBytes = message.getBytes();
        byte[] signatureBytes = decode(signature);
        Signature signatureVerify = Signature.getInstance("SHA256withRSA");
        signatureVerify.initVerify(publicKeyA);
        signatureVerify.update(messageToBytes);
        return signatureVerify.verify(signatureBytes);
    }

    //create digital signature for Bob
    public String signBPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKeyB);
        signature.update(messageToBytes);
        byte[] signatureBytes = signature.sign();
        return encode(signatureBytes);
    }

    //verify digital signature for Bob
    public boolean verifyBPub(String message, String signature) throws Exception {
        byte[] messageToBytes = message.getBytes();
        byte[] signatureBytes = decode(signature);
        Signature signatureVerify = Signature.getInstance("SHA256withRSA");
        signatureVerify.initVerify(publicKeyB);
        signatureVerify.update(messageToBytes);
        return signatureVerify.verify(signatureBytes);
    }

    //create digital signature for Charlie
    public String signCPriv(String message) throws Exception {
        byte[] messageToBytes = message.getBytes();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKeyC);
        signature.update(messageToBytes);
        byte[] signatureBytes = signature.sign();
        return encode(signatureBytes);
    }

    //verify digital signature for Charlie
    public boolean verifyCPub(String message, String signature) throws Exception {
        byte[] messageToBytes = message.getBytes();
        byte[] signatureBytes = decode(signature);
        Signature signatureVerify = Signature.getInstance("SHA256withRSA");
        signatureVerify.initVerify(publicKeyC);
        signatureVerify.update(messageToBytes);
        return signatureVerify.verify(signatureBytes);
    }


    public static void main(String[] args) {
        RSAProtocol rsa = new RSAProtocol();
        SymmetricKeyAuthentication aes = new SymmetricKeyAuthentication();
        byte[] KEY = "MZygpewJsCpRrfOr".getBytes();
        rsa.initFromStrings();


        try{
            String encryptedMessage = rsa.encryptKDCPub("Hello World");
            String decryptedMessage = rsa.decryptKDCPriv(encryptedMessage);

            String sig = rsa.signAPriv("hello");


            String enc = aes.encrypt("hello", KEY);
            String output = aes.decrypt(enc, KEY);
            System.err.println("Signature: "+sig);
            boolean verified = rsa.verifyAPub(output, sig);
            System.err.println("Verified: "+verified);

            System.err.println("KDC Encrypted:\n"+encryptedMessage);
            System.err.println("KDC Decrypted:\n"+decryptedMessage);

            encryptedMessage = rsa.encryptAPriv("Hello World");
            decryptedMessage = rsa.decryptAPub(encryptedMessage);

            System.err.println("Alice Encrypted:\n"+encryptedMessage);
            System.err.println("Alice Decrypted:\n"+decryptedMessage);

            encryptedMessage = rsa.encryptBPub("MZygpewJsCpRrfOr NonceA");
            decryptedMessage = rsa.decryptBPriv(encryptedMessage);

            System.err.println("Bob Encrypted:\n"+encryptedMessage);
            System.err.println("Bob Decrypted:\n"+decryptedMessage);

            encryptedMessage = rsa.encryptCPriv("Hello World");
            decryptedMessage = rsa.decryptCPub(encryptedMessage);

            System.err.println("Charlie Encrypted:\n"+encryptedMessage);
            System.err.println("Charlie Decrypted:\n"+decryptedMessage);


            rsa.printKeys();

        }catch (Exception ignored){}



    }
}
