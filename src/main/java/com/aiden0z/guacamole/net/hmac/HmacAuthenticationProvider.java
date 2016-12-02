package com.aiden0z.guacamole.net.hmac;

import com.google.inject.Guice;
import com.google.inject.Injector;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;

import java.util.Map;

public class HmacAuthenticationProvider extends SimpleAuthenticationProvider {

    private final Injector injector;

    public HmacAuthenticationProvider() throws GuacamoleException {
        injector = Guice.createInjector(new HmacAuthenticationProviderModule(this));
    }

    public HmacAuthenticationProvider(Injector injector) {
        this.injector = injector;
    }


    @Override
    public String getIdentifier() {
        return "hmac";
    }

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {

        AuthenticationProviderService authProviderService = injector.getInstance(AuthenticationProviderService.class);

        return authProviderService.getAuthorizedConfigurations(credentials.getRequest());

    }

}
