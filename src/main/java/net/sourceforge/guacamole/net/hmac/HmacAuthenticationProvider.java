package net.sourceforge.guacamole.net.hmac;

import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.net.auth.Credentials;
import net.sourceforge.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import net.sourceforge.guacamole.properties.GuacamoleProperties;
import net.sourceforge.guacamole.properties.StringGuacamoleProperty;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class HmacAuthenticationProvider extends SimpleAuthenticationProvider {
    public static final String SIGNATURE_PARAM = "signature";
    public static final String ID_PARAM = "id";
    public static final String PARAM_PREFIX = "guac.";

    private static final List<String> SIGNED_PARAMETERS = new ArrayList<String>() {{
        add("username");
        add("password");
        add("hostname");
        add("port");
    }};

    private SignatureVerifier signatureVerifier;

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

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {
        // Set up signed parameter verification
        if (signatureVerifier == null) {
            initFromProperties();
        }

        HttpServletRequest request = credentials.getRequest();

        String signature = request.getParameter(SIGNATURE_PARAM);

        if (signature == null) {
            return null;
        }
        signature = signature.replace(' ', '+');

        if (!checkTimestamp(request)) {
            return null;
        }

        GuacamoleConfiguration config = parseConfig(request);
        // Hostname is required!
        if (config.getParameter("hostname") == null) {
            return null;
        }

        StringBuilder message = new StringBuilder(config.getProtocol());

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

        Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        String id = request.getParameter(ID_PARAM);
        if (id == null) id = "DEFAULT";
        configs.put(id, config);
        return configs;
    }

    private boolean checkTimestamp(HttpServletRequest request) {
        // TODO - add a timestamp parameter to prevent replay attacks
        return true;
    }

    private GuacamoleConfiguration parseConfig(HttpServletRequest request) {
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
