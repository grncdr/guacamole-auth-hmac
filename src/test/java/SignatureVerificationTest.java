import net.sourceforge.guacamole.net.hmac.SignatureVerifier;

public class SignatureVerificationTest {
    public static void main(String[] args) {
        SignatureVerifier verifier = new SignatureVerifier("secret");
        // The test case data below was generated with the following PHP code:
        // echo base64_encode(hash_hmac('sha1', 'Arbitrary String', 'secret', true));
        if (verifier.verifySignature("nb42cSRCYM7jf7ZRCrLZ6e9d8p4=", "Arbitrary String")) {
            System.out.println("Verified signature for Arbitrary String");
        } else {
            System.out.println("Verification failed");
        }
    }
}
