package com.aiden0z.guacamole.net.hmac;

import com.google.inject.Inject;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.properties.LongGuacamoleProperty;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class AuthenticationProviderService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationProviderService.class);

    // guacamole server environment
    private final Environment environment;

    @Inject
    private TimeProvideService timeProvider;

    @Inject
    private HmacSignatureVerifyService signatureVerifier;


    // default protocol
    protected static final StringGuacamoleProperty DEFAULT_PROTOCOL = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "default-protocol"; }
    };

    // default timestamp
    protected static final LongGuacamoleProperty TIMESTAMP_AGE_LIMIT = new LongGuacamoleProperty() {
        @Override
        public String getName() { return "timestamp-age-limit"; }
    };

    protected static final long TEN_MINUTES = 10 * 60 * 1000;


    // these will be overridden by properties file if present
    private String defaultProtocol = "rdp";

    private long timestampAgeLimit = TEN_MINUTES; // 10 minutes

    // Per-request params
    protected static final String SIGNATURE_PARAM = "signature";
    // org.glyptodon.guacamole.net.basic.TunnelRequest.IDENTIFIER_PARAMETER;
    protected static final String ID_PARAM = "GUAC_ID";
    protected static final String TIMESTAMP_PARAM = "timestamp";
    protected static final String PARAM_PREFIX = "guac.";

    private static final List<String> SIGNED_PARAMETERS = new ArrayList<String>() {{
        add("username");
        add("password");
        add("hostname");
        add("port");
    }};


    @Inject
    public AuthenticationProviderService(Environment env) throws GuacamoleException {

        environment = env;

        defaultProtocol = environment.getProperty(DEFAULT_PROTOCOL, "rdp");
        timestampAgeLimit = environment.getProperty(TIMESTAMP_AGE_LIMIT, TEN_MINUTES);
    }

    public Map<String, GuacamoleConfiguration>  getAuthorizedConfigurations(HttpServletRequest request) throws GuacamoleException {

        String signature = request.getParameter(SIGNATURE_PARAM);

        logger.debug("Get hmac signature: {}", signature);

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

        StringBuilder message = new StringBuilder(timestamp).append(config.getProtocol());

        for (String name : SIGNED_PARAMETERS) {
            String value = config.getParameter(name);
            if (value == null) {
                continue;
            }
            message.append(name);
            message.append(value);
        }

        logger.debug("Get hmac message: {}", message.toString());

        // verify the signature
        if (!signatureVerifier.verifySignature(signature, message.toString())) {
            return null;
        }

        String id = request.getParameter(ID_PARAM);

        if (id == null) {
            id = "DEFAULT";
        }

        logger.debug("Get id parameter: {}", id);

        Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        configs.put(id, config);

        return configs;
    }

    private boolean checkTimestamp(String ts) {
        if (timestampAgeLimit == 0) {
            return true;
        }

        if (ts == null) {
            return false;
        }

        long timestamp = Long.parseLong(ts, 10);
        long now = timeProvider.currentTimeMillis();
        return timestamp + timestampAgeLimit > now;
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
}
