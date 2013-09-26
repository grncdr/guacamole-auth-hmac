package org.glyptodon.guacamole.net.hmac;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.UserContext;
import org.glyptodon.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionDirectory;
import org.glyptodon.guacamole.properties.GuacamoleProperties;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class HmacAuthenticationProvider extends SimpleAuthenticationProvider {

    private Logger logger = LoggerFactory.getLogger(HmacAuthenticationProvider.class);

    // Properties file params
    private static final StringGuacamoleProperty SECRET_KEY = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "secret-key"; }
    };

    private static final StringGuacamoleProperty DEFAULT_PROTOCOL = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "default-protocol"; }
    };

    // this will be overridden by properties file if present
    private String defaultProtocol = "rdp";


    // Per-request params
    public static final String SIGNATURE_PARAM = "signature";
    public static final String ID_PARAM = "id";
    public static final String TIMESTAMP_PARAM = "timestamp";
    public static final String PARAM_PREFIX = "guac.";
    public static final long TIMESTAMP_AGE_LIMIT = 10 * 60 * 1000; // 10 minutes

    private static final List<String> SIGNED_PARAMETERS = new ArrayList<String>() {{
        add("username");
        add("password");
        add("hostname");
        add("port");
    }};

    private SignatureVerifier signatureVerifier;

    private final TimeProviderInterface timeProvider;

    public HmacAuthenticationProvider(TimeProviderInterface timeProvider) {
        this.timeProvider = timeProvider;
    }

    public HmacAuthenticationProvider() {
        timeProvider = new DefaultTimeProvider();
    }

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {
        if (signatureVerifier == null) {
            initFromProperties();
        }

        GuacamoleConfiguration config = getGuacamoleConfiguration(credentials.getRequest());

        if (config == null) {
            return null;
        }

        Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        configs.put(config.getParameter("id"), config);
        return configs;
    }

    @Override
    public UserContext updateUserContext(UserContext context, Credentials credentials) throws GuacamoleException {
        HttpServletRequest request = credentials.getRequest();
        GuacamoleConfiguration config = getGuacamoleConfiguration(request);
        if (config == null) {
            return context;
        }
        String id = config.getParameter("id");
        SimpleConnectionDirectory connections = (SimpleConnectionDirectory) context.getRootConnectionGroup().getConnectionDirectory();
        SimpleConnection connection = new SimpleConnection(id, id, config);
        connections.putConnection(connection);
        return context;
    }

    private GuacamoleConfiguration getGuacamoleConfiguration(HttpServletRequest request) throws GuacamoleException {
        if (signatureVerifier == null) {
            initFromProperties();
        }
        String signature = request.getParameter(SIGNATURE_PARAM);

        if (signature == null) {
            return null;
        }
        signature = signature.replace(' ', '+');

        String timestamp = request.getParameter(TIMESTAMP_PARAM);
        if (!checkTimestamp(timestamp)) {
            return null;
        }

        GuacamoleConfiguration config = parseConfigParams(request);

        // Hostname is required!
        if (config.getParameter("hostname") == null) {
            return null;
        }

        // Hostname is required!
        if (config.getProtocol() == null) {
            return null;
        }

        StringBuilder message = new StringBuilder(timestamp)
                .append(config.getProtocol());

        for (String name : SIGNED_PARAMETERS) {
            String value = config.getParameter(name);
            if (value == null) {
                continue;
            }
            message.append(name);
            message.append(value);
        }

        if (!signatureVerifier.verifySignature(signature, message.toString())) {
            return null;
        }
        String id = request.getParameter(ID_PARAM);
        if (id == null) {
            id = "DEFAULT";
        } else {
        	// This should really use BasicGuacamoleTunnelServlet's IdentfierType, but it is private!
        	// Currently, the only prefixes are both 2 characters in length, but this could become invalid at some point.
        	// see: org/glyptodon/guacamole/net/basic/BasicGuacamoleTunnelServlet.java:244-252
        	id = id.substring(2);
        }
        // This isn't normally part of the config, but it makes it much easier to return a single object
        config.setParameter("id", id);
        return config;
    }

    private boolean checkTimestamp(String ts) {
        if (ts == null) {
            return false;
        }
        long timestamp = Long.parseLong(ts, 10);
        long now = timeProvider.currentTimeMillis();
        return Math.abs(timestamp - now) < TIMESTAMP_AGE_LIMIT;
    }

    private GuacamoleConfiguration parseConfigParams(HttpServletRequest request) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();

        Map<String, String[]> params = request.getParameterMap();

        for (String name : params.keySet()) {
            String value = request.getParameter(name);
            if (!name.startsWith(PARAM_PREFIX) || value == null || value.length() == 0) {
                continue;
            }
            else if (name.equals(PARAM_PREFIX + "protocol")) {
                config.setProtocol(request.getParameter(name));
            }
            else {
                config.setParameter(name.substring(PARAM_PREFIX.length()), request.getParameter(name));
            }
        }

        if (config.getProtocol() == null) config.setProtocol(defaultProtocol);

        return config;
    }

    private void initFromProperties() throws GuacamoleException {
        String secretKey = GuacamoleProperties.getRequiredProperty(SECRET_KEY);
        signatureVerifier = new SignatureVerifier(secretKey);
        defaultProtocol = GuacamoleProperties.getProperty(DEFAULT_PROTOCOL);
        if (defaultProtocol == null) defaultProtocol = "rdp";
    }
}
