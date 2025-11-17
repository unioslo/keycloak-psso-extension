/* Copyright 2025 University of Oslo, Norway
 # This file is part of Cerebrum.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/

package no.uio.keycloak.psso.token;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;


import java.util.*;

public class PlatformSSONonceProtocolMapper extends AbstractOIDCProtocolMapper {

    public static final String PROVIDER_ID = "psso-nonce-mapper";
    public static final String NONCE_ATTRIBUTE = "psso_nonce";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name("claim.name")
                .label("Claim name")
                .helpText("The name of the nonce claim")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("nonce")
                .add()
                .build();
    }

    public PlatformSSONonceProtocolMapper() {}

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getDisplayType() {
        return "PSSO Nonce Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds the Platform SSO nonce claim into the ID Token.";
    }

    @Override
    public IDToken transformIDToken(
            org.keycloak.representations.IDToken token,
            org.keycloak.models.ProtocolMapperModel mappingModel,
            org.keycloak.models.KeycloakSession session,
            org.keycloak.models.UserSessionModel userSession,
            org.keycloak.models.ClientSessionContext clientSessionCtx) {

        // get nonce from client session notes
        String nonce = clientSessionCtx.getAttribute("psso_nonce", String.class);
        if (nonce == null || nonce.isBlank()) {
            return token;
        }

        // retrieve custom claim name from mapper config
        String claimName = mappingModel.getConfig().getOrDefault("claim.name", "nonce");

        // inject into ID token
        token.getOtherClaims().put(claimName, nonce);
        return token;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    // ...

    public static ProtocolMapperModel create(String name, String claimName) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<>();

        // token claim name config (uses constant defined by Keycloak helper)
        config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, claimName);

        // include flags: include in id token, not in access token, not in userinfo, not in introspection
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "false");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "false");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "false");

        mapper.setConfig(config);
        return mapper;
    }
}
