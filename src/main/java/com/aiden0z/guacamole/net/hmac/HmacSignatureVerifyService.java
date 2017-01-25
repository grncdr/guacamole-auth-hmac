package com.aiden0z.guacamole.net.hmac;

import com.google.inject.Inject;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HmacSignatureVerifyService {

    private final SecretKeySpec secretKey;

    static final StringGuacamoleProperty SECRET_KEY = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "secret-key";
        }
    };

    @Inject
    public HmacSignatureVerifyService(Environment env) throws GuacamoleException {
        this.secretKey = new SecretKeySpec(env.getRequiredProperty(SECRET_KEY).getBytes(), "HmacSHA1");
    }

    public boolean verifySignature(String signature, String message) {
        try {
            Mac mac = createMac();
            String expected = Base64.encode(mac.doFinal(message.getBytes()));
            return signature.equals(expected);
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
