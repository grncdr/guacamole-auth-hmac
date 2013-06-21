package net.sourceforge.guacacmole.net.hmac;

import junit.framework.TestCase;
import net.sourceforge.guacamole.net.hmac.SignatureVerifier;

public class SignatureVerifierTest extends TestCase {
    private SignatureVerifier verifier;

    public void setUp() {
        verifier = new SignatureVerifier("secret");
    }

    public void testSuccessCase() {
        // The test case data below was generated with the following PHP code:
        // echo base64_encode(hash_hmac('sha1', 'Arbitrary String', 'secret', true));
        assertTrue(verifier.verifySignature("nb42cSRCYM7jf7ZRCrLZ6e9d8p4=", "Arbitrary String"));
    }

    public void testFailureCase() {
        assertFalse(verifier.verifySignature("Definitely not the right signature", "Arbitrary String"));
    }
}
