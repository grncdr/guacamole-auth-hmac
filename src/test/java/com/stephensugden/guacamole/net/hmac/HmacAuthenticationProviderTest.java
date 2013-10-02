package com.stephensugden.guacamole.net.hmac;

import junit.framework.TestCase;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static com.stephensugden.guacamole.net.hmac.HmacAuthenticationProvider.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HmacAuthenticationProviderTest extends TestCase {

    public void testSuccess() throws GuacamoleException {
        final String connectionId = "c/my-connection";

        HttpServletRequest request = mockRequest(new HashMap<String, String>() {{
            put(ID_PARAM,        connectionId);
            put("timestamp",     "1373563683000");
            put("guac.hostname", "10.2.3.4");
            put("guac.protocol", "rdp");
            put("guac.port",     "3389");
            // Test signature was generated with the following PHP snippet
            // base64_encode(hash_hmac('sha1', '1373563683000rdphostname10.2.3.4port3389', 'secret', true));
            put(SIGNATURE_PARAM, "6PHOr00TnhA10Ef9I4bLqeSXKYg=");
        }});

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProviderInterface timeProvider = mock(TimeProviderInterface.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L);
        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(timeProvider);

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get(connectionId.substring(2));
        assertNotNull(config);
        assertEquals("rdp", config.getProtocol());
    }

    private static HttpServletRequest mockRequest(final Map<String, String> queryParams) {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(anyString())).then(new Answer<Object>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                return queryParams.get(key);
            }
        });

        // Note this is invalidating the servlet API, but I only use the keys so I don't care
        when(request.getParameterMap()).thenReturn(queryParams);

        return request;
    }
}
