package com.aiden0z.guacamole.net.hmac;

import com.google.inject.*;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;

import junit.framework.TestCase;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;

import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HmacSignatureVerifyServiceTest extends TestCase {

    private static String secretKey = "secret_key";

    @Bind private Environment environment;

    @Inject
    private
    HmacSignatureVerifyService signatureService;


    @Before
    public void setUp() throws GuacamoleException {
        environment = mock(Environment.class);
        when(environment.getRequiredProperty(HmacSignatureVerifyService.SECRET_KEY)).thenReturn(secretKey);

        // Guice BoundFieldModule
        // https://github.com/google/guice/wiki/BoundFields
        Guice.createInjector(BoundFieldModule.of(this)).injectMembers(this);
    }

    @Test
    public void testVerifySuccess() {

        assertTrue(signatureService.verifySignature("3IW0Z3jesJexe6oU3HGo4I7yxeY=", "guacamole-hmac-auth"));
    }

    @Test
    public void testVerifyFailed() {
        assertFalse(signatureService.verifySignature("invalid_signature", "gucamole-hmac-auth"));
    }


}
