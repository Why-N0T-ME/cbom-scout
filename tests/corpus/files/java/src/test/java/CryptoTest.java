import java.security.MessageDigest;

class CryptoTest {
    Object md = digest();

    Object digest() throws Exception {
        return MessageDigest.getInstance("SHA-1");
    }
}
