package net.sourceforge.guacamole.net.openstack;

import com.woorea.openstack.base.client.OpenStackClientConnector;
import com.woorea.openstack.connector.JaxRs20Connector;
import com.woorea.openstack.keystone.Keystone;
import com.woorea.openstack.keystone.model.Access;
import com.woorea.openstack.keystone.model.Authentication;
import com.woorea.openstack.keystone.model.authentication.UsernamePassword;
import com.woorea.openstack.keystone.utils.KeystoneUtils;
import com.woorea.openstack.nova.Nova;
import com.woorea.openstack.nova.model.Server;
import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.net.auth.Credentials;
import net.sourceforge.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import net.sourceforge.guacamole.net.hmac.SignatureVerifier;
import net.sourceforge.guacamole.properties.GuacamoleProperties;
import net.sourceforge.guacamole.properties.StringGuacamoleProperty;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ProcessingException;
import java.util.*;

public class OpenStackAuthenticationProvider extends SimpleAuthenticationProvider {
    public static final String SIGNATURE_PARAM = "signature";
    public static final String SERVER_PARAM = "server_id";
    public static final String ID_PARAM = "id";

    private SignatureVerifier signatureVerifier;

    private Nova nova;
    private Keystone keystone;
    private OpenStackClientConnector connector;

    private static final Map<String, String> protocolPort = new HashMap<String, String>() {{
        put("rdp", "3839");
        put("vnc", "5900");
        put("console", "5900");
    }};

    public static final StringGuacamoleProperty SECRET_KEY = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "secret-key"; }
    };

    public static final StringGuacamoleProperty OPEN_STACK_AUTH_URI = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "open-stack-auth-uri"; }
    };

    public static final StringGuacamoleProperty OPEN_STACK_PASSWORD = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "open-stack-password"; }
    };

    public static final StringGuacamoleProperty OPEN_STACK_USERNAME = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "open-stack-username"; }
    };

    public static final StringGuacamoleProperty OPEN_STACK_TENANT_NAME = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "open-stack-tenant-name"; }
    };

    public void setNova(Nova nova) {
        this.nova = nova;
    }
    public void setSignatureVerifier(SignatureVerifier signatureVerifier) {
        this.signatureVerifier = signatureVerifier;
    }

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {
        if (nova == null) {
            initFromProperties();
        }
        HttpServletRequest request = credentials.getRequest();
        String serverId = getVerifiedServerId(request);
        if (serverId == null)
            return null;

        Server server;

        try {
            server = nova.servers().show(serverId).execute();
        } catch (ProcessingException processingException) {
            return null;
        }

        if (server == null)
            return null;

        String publicAddress = getPublicAddress(server);

        if (publicAddress == null)
            return null;

        String protocol = request.getParameter("protocol");

        if (protocol == null) {
            protocol = "rdp";
        }

        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol(protocol);
        config.setParameter("port", protocolPort.get(protocol));
        config.setParameter("hostname", publicAddress);

        String connectionId = request.getParameter("id");

        Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();
        configs.put(connectionId, config);
        return configs;
    }

    private String getPublicAddress(Server server) {
        Server.Addresses addresses = server.getAddresses();
        Map<String, List<Server.Addresses.Address>> tmp = addresses.getAddresses();
        for (String key : tmp.keySet()) {
            for (Server.Addresses.Address address : tmp.get(key)) {
                if (address.getType().equals("floating"))
                    return address.getAddr();
            }
        }
        return null;
    }

    private String getVerifiedServerId(HttpServletRequest request) {
        String serverId = request.getParameter(SERVER_PARAM);
        String signature = request.getParameter(SIGNATURE_PARAM);
        if (serverId != null && signature != null && signatureVerifier.verifySignature(signature, serverId))
             return serverId;

        return null;
    }

    private String getConnectionIdFromRequest(HttpServletRequest request) {
        Map<String, String[]> params = request.getParameterMap();
        String[] idTemp = params.get("id");
        if (idTemp == null || idTemp.length == 0) {
            return null;
        }

        return idTemp[0];
    }

    private String getServerNameFromRequest(HttpServletRequest request) {
        String connectionId = getConnectionIdFromRequest(request);
        List<String> parts = Arrays.asList(connectionId.split("."));
        parts.remove(parts.size() - 1);
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            sb.append(part);
        }
        return sb.toString();
    }

    private void initFromProperties() throws GuacamoleException {
        String authUri = GuacamoleProperties.getRequiredProperty(OPEN_STACK_AUTH_URI);
        connector = new JaxRs20Connector();
        keystone = new Keystone(authUri, connector);

        String username = GuacamoleProperties.getRequiredProperty(OPEN_STACK_USERNAME);
        String password = GuacamoleProperties.getRequiredProperty(OPEN_STACK_PASSWORD);
        String tenantName = GuacamoleProperties.getRequiredProperty(OPEN_STACK_TENANT_NAME);

        Authentication authentication;
        authentication = new UsernamePassword(username, password);

        Access access = keystone
                .tokens()
                .authenticate(authentication)
                .withTenantName(tenantName)
                .execute();

        keystone.token(access.getToken().getId());

        String novaEndpoint = KeystoneUtils.findEndpointURL(
                access.getServiceCatalog(),
                "compute",
                "RegionOne",
                "public"
        );
        nova = new Nova(novaEndpoint, connector);
        nova.token(access.getToken().getId());

        // Set up signed parameter verification
        if (signatureVerifier == null) {
            String secretKey = GuacamoleProperties.getRequiredProperty(SECRET_KEY);
            signatureVerifier = new SignatureVerifier(secretKey);
        }
    }

}
