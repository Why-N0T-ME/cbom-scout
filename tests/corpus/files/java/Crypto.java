import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KEM;

public class Crypto {
    // Cipher legacy = Cipher.getInstance("DES");
    /* MessageDigest.getInstance("MD5");
       Signature.getInstance("SHA1withRSA"); */
    /** 예전에는 Cipher.getInstance("RC4") 를 썼다. */
    String doc = "Cipher.getInstance(\"DESede\") 금지";
    String tb = """
        MessageDigest.getInstance("SHA-1")
        """;
    String url = "http://example.com"; // KeyAgreement.getInstance("DH")
    int md5Count = 0;
    String aesMode = "aes";

    void run() throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        MessageDigest md = MessageDigest.getInstance("MD5");
        Signature s = Signature.getInstance("SHA256withRSA");
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        // g.initialize(4096);
        g.initialize(1024);
        KEM kem = KEM.getInstance("ML-KEM-768");
        log("ML-KEM-1024 검토 중");
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
    }

    void log(String m) {}
}
