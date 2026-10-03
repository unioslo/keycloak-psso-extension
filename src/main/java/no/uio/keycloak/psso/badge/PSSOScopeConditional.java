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

package no.uio.keycloak.psso.badge;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import java.util.Arrays;

/**
 * Matches on a scope in the original authorization request, so a realm can run the badge
 * sub-flow only for Platform SSO web logins.
 *
 * <p>Platform SSO merges {@code urn:apple:platformsso} into the scope parameter on its way
 * to the IdP, and AuthorizationEndpoint copies the scope parameter into a client note, so
 * the value is readable here before anyone has logged in.
 *
 * <p>Unlike {@link no.uio.keycloak.psso.PSSOConditional}, which inspects the method a user
 * already authenticated with, this one runs <em>before</em> identity exists.
 *
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSOScopeConditional implements ConditionalAuthenticator {

    private static final Logger logger = Logger.getLogger(PSSOScopeConditional.class);

    public static final PSSOScopeConditional SINGLETON = new PSSOScopeConditional();

    public static final String CONF_SCOPE = "psso_scope";
    public static final String CONF_INVERT = "psso_scope_invert";
    public static final String DEFAULT_SCOPE = "urn:apple:platformsso";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String wanted = DEFAULT_SCOPE;
        boolean invert = false;
        if (config != null && config.getConfig() != null) {
            String configured = config.getConfig().get(CONF_SCOPE);
            if (configured != null && !configured.isBlank()) {
                wanted = configured.trim();
            }
            invert = Boolean.parseBoolean(config.getConfig().get(CONF_INVERT));
        }

        String scope = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);
        logger.debugf("Platform SSO: scope conditional looking for '%s' in '%s' (invert=%s)",
                wanted, scope, invert);

        return hasScope(scope, wanted) ^ invert;
    }

    /** Scope is a space-delimited list, so a substring test would match too much. */
    private static boolean hasScope(String scope, String wanted) {
        if (scope == null || scope.isBlank()) {
            return false;
        }
        return Arrays.asList(scope.trim().split("\\s+")).contains(wanted);
    }

    /**
     * Must be false: this runs before the user is known, which is the whole point of gating
     * a first-factor sub-flow with it.
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public void close() {
        // Not used
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }
}
