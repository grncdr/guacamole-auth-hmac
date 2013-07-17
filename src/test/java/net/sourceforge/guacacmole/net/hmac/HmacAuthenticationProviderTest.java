package net.sourceforge.guacacmole.net.hmac;

import junit.framework.TestCase;
import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.net.auth.Credentials;
import net.sourceforge.guacamole.net.hmac.HmacAuthenticationProvider;
import net.sourceforge.guacamole.net.hmac.SignatureVerifier;
import net.sourceforge.guacamole.net.hmac.TimeProviderInterface;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static net.sourceforge.guacamole.net.hmac.HmacAuthenticationProvider.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HmacAuthenticationProviderTest extends TestCase {

    public void testSuccess() throws GuacamoleException {
        // Test signature was generated with the following PHP snippet
        // base64_encode(hash_hmac('sha1', 'rdphostname10.2.3.4', 'secret', true));
        HttpServletRequest request = mockRequest(new HashMap<String, String>() {{
            put(ID_PARAM, "reservation_55.sys1");
            put(SIGNATURE_PARAM, "xgWvnyVtp0ISLiGQ+kmsTbH2rcM=");
            put("guac.hostname", "10.2.3.4");
            put("guac.protocol", "rdp");
        }});

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
        when(signatureVerifier.verifySignature(anyString(), anyString())).thenReturn(true);

        TimeProviderInterface timeProvider = mock(TimeProviderInterface.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L);
        // http://bf-moodle.hatsize.int/guacamole/client.xhtml?id=DEFAULT&timestamp=1373563683000&signature=sACLU6NO17Yl922xnhkih7/RXTs=
        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(timeProvider);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get("connection-id");
        assertNotNull(config);
        assertEquals("rdp", config.getProtocol());
    }

    private static HttpServletRequest mockRequest(Map<String, String> queryParams) {

        Map<String, String[]> requestQueryParams = new HashMap<String, String[]>();
        for (String name : queryParams.keySet()) {
            String[] param = {queryParams.get(name)};
            requestQueryParams.put(name, param);
        }

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(ID_PARAM)).thenReturn(queryParams.get(ID_PARAM));
        when(request.getParameter(SIGNATURE_PARAM)).thenReturn(queryParams.get(SIGNATURE_PARAM));
        when(request.getParameterMap()).thenReturn(requestQueryParams);

        return request;
    }
}
