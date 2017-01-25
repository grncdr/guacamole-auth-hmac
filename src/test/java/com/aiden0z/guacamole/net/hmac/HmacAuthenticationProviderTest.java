package com.aiden0z.guacamole.net.hmac;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;


import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static com.aiden0z.guacamole.net.hmac.AuthenticationProviderService.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;


public class HmacAuthenticationProviderTest extends TestCase {

    private static final long ONE_HOUR = 60000L;
    private static final String connectionId = "my-connection";
    private static final String secretKey = "secret";

    private Environment environment;


    @Before
    public void setUp() throws Exception {

        environment = mock(Environment.class);

        when(environment.getRequiredProperty(HmacSignatureVerifyService.SECRET_KEY)).thenReturn(secretKey);

        when(environment.getProperty(DEFAULT_PROTOCOL)).thenReturn("rdp");
        when(environment.getProperty(TIMESTAMP_AGE_LIMIT, TEN_MINUTES)).thenReturn(ONE_HOUR);

    }

    private Injector getInjector(final TimeProvideService timeProvider) {

        return Guice.createInjector(
                new AbstractModule() {
                    @Override
                    protected void configure() {

                        bind(Environment.class).toInstance(environment);
                        bind(HmacSignatureVerifyService.class);
                        bind(TimeProvideService.class).toInstance(timeProvider);
                    }
                }
        );
    }

    private HttpServletRequest getHttpServletRequest() {
        return getHttpServletRequest(connectionId);
    }

    private HttpServletRequest getHttpServletRequest(final String connectionId) {
        return mockRequest(new HashMap<String, String>() {{
            put(ID_PARAM, connectionId);
            put("timestamp", "1373563683000");
            put("guac.hostname", "10.2.3.4");
            put("guac.protocol", "rdp");
            put("guac.port", "3389");
            // Test signature was generated with the following PHP snippet
            // base64_encode(hash_hmac('sha1', '1373563683000rdphostname10.2.3.4port3389', 'secret', true));
            put(SIGNATURE_PARAM, "6PHOr00TnhA10Ef9I4bLqeSXKYg=");
        }});
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

    @Test
    public void testSuccess() throws GuacamoleException {
        HttpServletRequest request = getHttpServletRequest();

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProvideService timeProvider = mock(TimeProvideService.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L);

        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(getInjector(timeProvider));

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get(connectionId);
        assertNotNull(config);
        assertEquals("rdp", config.getProtocol());
    }

    @Test
    public void testHostnameFailure() throws GuacamoleException {

        HttpServletRequest request = mockRequest(new HashMap<String, String>() {{
            put(ID_PARAM, connectionId);
            put("timestamp", "1373563683000");
            put("guac.hostname", "10.2.3.5");  // changed hostname should invalidate signature
            put("guac.protocol", "rdp");
            put("guac.port", "3389");
            // Test signature was generated with the following PHP snippet
            // base64_encode(hash_hmac('sha1', '1373563683000rdphostname10.2.3.4port3389', 'secret', true));
            put(SIGNATURE_PARAM, "6PHOr00TnhA10Ef9I4bLqeSXKYg=");
        }});

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProvideService timeProvider = mock(TimeProvideService.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L);

        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(getInjector(timeProvider));

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);
        assertNull(configs);
    }

    @Test
    public void testTimestampFresh() throws Exception {
        HttpServletRequest request = getHttpServletRequest();

        Credentials credentials = new Credentials();
        credentials.setRequest(request);

        TimeProvideService timeProvider = mock(TimeProvideService.class);
        when(timeProvider.currentTimeMillis()).thenReturn(1373563683000L + ONE_HOUR - 1l);

        HmacAuthenticationProvider authProvider = new HmacAuthenticationProvider(getInjector(timeProvider));

        Map<String, GuacamoleConfiguration> configs = authProvider.getAuthorizedConfigurations(credentials);

        assertNotNull(configs);
        assertEquals(1, configs.size());
        GuacamoleConfiguration config = configs.get(connectionId);
        assertNotNull(config);
    }

}
