import net.sourceforge.guacamole.net.auth.Credentials;
import net.sourceforge.guacamole.net.hmac.HmacAuthenticationProvider;
import net.sourceforge.guacamole.net.hmac.SignatureVerifier;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static net.sourceforge.guacamole.net.hmac.HmacAuthenticationProvider.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SmokeTest {
    public static void main(String[] args) throws Exception {
        // Query parameters

        // Signature was generated with the following PHP snippet
        // base64_encode(hash_hmac('sha1', 'rdphostname10.2.3.4', 'secret', true));
        final String[] signature = {"xgWvnyVtp0ISLiGQ+kmsTbH2rcM="};
        final String[] connectionId = {"connection-id"};
        final String[] hostname = {"10.2.3.4"};
        final String[] port = {"3389"};
        final String[] protocol = {"rdp"};
        Map<String, String[]> queryParams = new HashMap<String, String[]>() {{
            put(ID_PARAM, connectionId);
            put(SIGNATURE_PARAM, signature);
            put("guac.hostname", hostname);
            put("guac.protocol", protocol);
        }};

        Credentials credentials = new Credentials();
        HttpServletRequest request = mock(HttpServletRequest.class);
        credentials.setRequest(request);

        when(request.getParameter(ID_PARAM)).thenReturn(queryParams.get(ID_PARAM)[0]);
        when(request.getParameter(SIGNATURE_PARAM)).thenReturn(queryParams.get(SIGNATURE_PARAM)[0]);
        when(request.getParameterMap()).thenReturn(queryParams);

        SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
        when(signatureVerifier.verifySignature(anyString(), anyString())).thenReturn(true);

        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider();

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        if (configs == null) {
            System.out.println("configs == null");
            System.exit(1);
        }
        System.out.println("All done, awesome!");
    }
}
