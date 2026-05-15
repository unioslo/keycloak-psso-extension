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

import jakarta.ws.rs.core.HttpHeaders;
import no.uio.keycloak.psso.token.RefreshTokenValidator;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.representations.RefreshToken;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSORegistrationAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(PSSORegistrationAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        String pSssoHeader = headers.getHeaderString("Authorization-Setup-Assistant-PSSO");
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

            logger.info("Platform SSO Simple Authentication request: " + requestData);
            pSssoHeader = pSssoHeader.replaceFirst("^[Bb]earer\\s+", "");
            RefreshTokenValidator validator = new RefreshTokenValidator(context.getSession());
            try {
                RefreshToken refreshToken = validator.validate(pSssoHeader, "psso");
                UserModel user = context.getSession().users().getUserById(context.getRealm(), refreshToken.getSubject());
                if (user == null) {
                    context.attempted();
                    return;
                }

                context.setUser(user);
                context.success();
                return;

            } catch (Exception e) {
                logger.error("Platform SSO: Simple Authentication attempt failed. " + requestData);
                logger.error(e);
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