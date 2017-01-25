package com.aiden0z.guacamole.net.hmac;

import com.google.inject.AbstractModule;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.environment.LocalEnvironment;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;

public class HmacAuthenticationProviderModule  extends AbstractModule {

    private final Environment environment;
    private AuthenticationProvider authProvider;

    public HmacAuthenticationProviderModule(AuthenticationProvider authProvider) throws GuacamoleException {
        this.environment = new LocalEnvironment();

        this.authProvider = authProvider;
    }

    @Override
    protected void configure() {

        bind(AuthenticationProvider.class).toInstance(authProvider);
        bind(Environment.class).toInstance(environment);

        // Bind service
        bind(HmacSignatureVerifyService.class);
        bind(TimeProvideService.class).to(DefaultTimeProvideService.class);
    }
}
