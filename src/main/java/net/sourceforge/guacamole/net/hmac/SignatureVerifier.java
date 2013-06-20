package net.sourceforge.guacamole.net.hmac;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SignatureVerifier {
    private final SecretKeySpec secretKey;

    public SignatureVerifier(String secretKey) {
        this.secretKey = new SecretKeySpec(secretKey.getBytes(), "HmacSHA1");
    }

    public boolean verifySignature(String signature, String message) {
        try {
            Mac mac = createMac();
            byte[] digest = mac.doFinal(message.getBytes());
            return Base64.encode(digest).equals(signature);
        } catch (InvalidKeyException e) {
            return false;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    Mac createMac() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        return mac;
    }
}