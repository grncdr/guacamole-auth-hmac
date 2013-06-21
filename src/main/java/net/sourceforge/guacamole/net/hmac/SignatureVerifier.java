package net.sourceforge.guacamole.net.hmac;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.slf4j.LoggerFactory.getLogger;

public class SignatureVerifier {
    private final SecretKeySpec secretKey;

    private Logger logger = getLogger(SignatureVerifier.class);

    public SignatureVerifier(String secretKey) {
        this.secretKey = new SecretKeySpec(secretKey.getBytes(), "HmacSHA1");
    }

    public boolean verifySignature(String signature, String message) {
        try {
            Mac mac = createMac();
            String expected = Base64.encode(mac.doFinal(message.getBytes()));
            boolean result = signature.equals(expected);
            if (!result) {
                logger.debug(
                    "Invalid signature for message: " + message +
                    "\n  expected: " + expected +
                    "\n  received: " + signature
                );
            }
            return result;
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