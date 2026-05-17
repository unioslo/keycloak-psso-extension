/* Copyright 2025 University of Oslo, Norway
 # This file is part of the Keycloak Platform SSO Extension codebase.
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

package no.uio.keycloak.psso;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import no.uio.keycloak.psso.token.IDTokenValidator;
import no.uio.keycloak.psso.token.RefreshTokenValidator;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSORegistrationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(PSSORegistrationAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        String pSssoHeader = headers.getHeaderString("Platform-SSO-Authorization");
        String ip_address = "";
        String userAgent = "";
        try {
            ip_address = context.getSession().getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
            userAgent = context.getSession().getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        } catch (Exception e) {
            logger.error("Platform SSO: Error getting ip address from user");
        }
        String requestData = "IP Address: " + ip_address + " User Agent: " + userAgent;
        if (pSssoHeader != null) {
            if (pSssoHeader != null) {
                logger.info("Platform SSO Authentication Request: " + requestData);
                pSssoHeader = pSssoHeader.replaceFirst("^[Bb]earer\\s+", "");
                String ssoIdB64;
                String sigB64;
                try {
                    String[] split = pSssoHeader.split("\\.");
                    ssoIdB64 = split[0];
                    sigB64 = split[1];
                } catch (Exception e) {
                    logger.error("Platform SSO: Wrong SSO header format. " + requestData);
                    logger.error(e);
                    context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
                    return;

                }

                byte[] tokenBytes = PSSOAuthenticator.base64UrlDecode(ssoIdB64);
                byte[] signatureBytes = PSSOAuthenticator.base64UrlDecode(sigB64);
                ObjectMapper mapper = new ObjectMapper();
                JsonNode env;
                try {
                    env = mapper.readTree(tokenBytes);
                } catch (Exception e) {

                    logger.error("Platform SSO: Error parsing SSO Token. " + e.getMessage());
                    logger.error("Platform SSO: Authentication attempt failed. " + requestData);

                    context.attempted();
                    return;
                }
                RealmModel realm = context.getRealm();
                String preferred_username = env.get("username").asText();
                String tokenString = env.get("token").asText();
                String username ;
                String serial;

                KeycloakSession session = context.getSession();
                RefreshToken refreshToken;

                RefreshTokenValidator validator = new RefreshTokenValidator(session);
                try {
                    refreshToken = validator.validate(tokenString, "psso");
                    username = refreshToken.getPreferredUsername();
                    serial = refreshToken.getOtherClaims().get("macSerial").toString();



                } catch (Exception e) {
                    logger.error("Platform SSO: Invalid refresh token: " + e + "   " + requestData);
                    context.attempted();
                    return;
                }
                if (PSSOAuthenticator.verifySignature(context, env, ssoIdB64, sigB64, signatureBytes, serial)) {



                    if (username != null && username.equals(preferred_username)) {
                        context.setUser(session.users().getUserByUsername(realm, username));
                        context.success();
                        logger.info("Platform SSO: Authentication successful for user: "+ username + requestData + " device serial: "+serial);
                        return;
                    }
                }
            }else {
                context.attempted();

            }
        }
        context.attempted();
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}