package net.sourceforge.guacamole.net.hmac;

import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.net.auth.Credentials;
import net.sourceforge.guacamole.net.auth.UserContext;
import net.sourceforge.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import net.sourceforge.guacamole.net.auth.simple.SimpleConnectionDirectory;
import net.sourceforge.guacamole.properties.GuacamoleProperties;
import net.sourceforge.guacamole.properties.StringGuacamoleProperty;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;
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
        GuacamoleConfiguration config = getGuacamoleConfiguration(credentials.getRequest());
        if (config == null) {
            return context;
        }
        SimpleConnectionDirectory connections = (SimpleConnectionDirectory) context.getConnectionDirectory();
        connections.putConfig(config.getParameter("id"), config);
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

        String timestamp = request.getParameter("timestamp");
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
        long now = System.currentTimeMillis();
        return Math.abs(timestamp - now) < TIMESTAMP_AGE_LIMIT;
    }

    private GuacamoleConfiguration parseConfigParams(HttpServletRequest request) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();

        Map<String, String[]> params = request.getParameterMap();

        for (String name : params.keySet()) {
            if (!name.startsWith(PARAM_PREFIX) || params.get(name).length == 0) {
                continue;
            }
            else if (name.equals(PARAM_PREFIX + "protocol")) {
                config.setProtocol(params.get(name)[0]);
            }
            else {
                config.setParameter(name.substring(PARAM_PREFIX.length()), params.get(name)[0]);
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
