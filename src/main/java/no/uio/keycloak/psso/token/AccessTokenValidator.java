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
package no.uio.keycloak.psso.token;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;

import java.util.Map;
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class AccessTokenValidator {

    private final KeycloakSession session;
    private final RealmModel realm;

    public AccessTokenValidator(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    /**
     * Validates an AccessToken using Keycloak's internal signature verifier plus
     * additional security checks that decode() does NOT perform.
     *
     * @param tokenString the raw JWT
     * @param expectedClient the client id this token must be issued for (may be null if you don't want to enforce)
     * @return AccessToken if valid
     * @throws WebApplicationException if invalid
     */
    public AccessToken validate(String tokenString, String expectedClient) {
        AccessToken token;

        // 1. Signature + parsing
        try {
            token = session.tokens().decode(tokenString, AccessToken.class);
        } catch (Exception e) {
            throw unauthorized("Invalid token or signature");
        }

        if (token == null) {
            throw unauthorized("Malformed token");
        }

        // 2. Expiration
        if (token.getExp() != 0 &&
                token.getExp() < org.keycloak.common.util.Time.currentTime()) {
            throw unauthorized("Token expired");
        }

        // 3. Issuer check (required)
        String expectedIssuer = session.getContext().getUri().getBaseUriBuilder()
                .path("realms")
                .path(realm.getName())
                .build()
                .toString();

        if (!expectedIssuer.equals(token.getIssuer())) {
            throw unauthorized("Invalid issuer");
        }

        // 4. Audience / client binding
        if (expectedClient != null) {
            String[] audience = token.getAudience();

            boolean audienceOk = false;

            if (audience != null) {
                for (String aud : audience) {
                    if (expectedClient.equals(aud)) {
                        audienceOk = true;
                        break;
                    }
                }
            }

            // azp = "authorized party" (the client id)
            if (token.getIssuedFor() != null) {
                audienceOk = audienceOk || token.getIssuedFor().equals(expectedClient);
            }
            if (token.getOtherClaims().get("azp") != null) {
                audienceOk = audienceOk || token.getOtherClaims().get("azp").equals(expectedClient);
            }

            if (!audienceOk) {
                throw unauthorized("Token not issued for client " + expectedClient);
            }
        }

        // 5. Check if the session is still active
        String sessionState = token.getSessionState();
        if (sessionState == null) {
            throw unauthorized("Token missing session state");
        }

        var userSession = session.sessions().getUserSession(realm, sessionState);
        if (userSession == null) {
            throw unauthorized("User session expired or logged out");
        }

        // 6. Basic user check
        UserModel user = session.users().getUserById(realm, token.getSubject());
        if (user == null) {
            throw unauthorized("User does not exist");
        }

        return token;
    }

    private WebApplicationException unauthorized(String msg) {
        return new WebApplicationException(
                Response.status(Response.Status.UNAUTHORIZED)
                        .entity(Map.of("error", msg))
                        .build());
    }
}
