/* Copyright 2026 University of Oslo, Norway
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
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;

import org.keycloak.models.AuthenticatorConfigModel;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;



/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSOConditional implements  ConditionalAuthenticator {

    private static Logger logger = Logger.getLogger(PSSOConditional.class);
    public static final PSSOConditional SINGLETON = new PSSOConditional();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String psso_auth_method_cond = config.getConfig().get("psso_auth_method");
        String psso_auth_method_invert = config.getConfig().get("psso_auth_method_invert");

        String psso_auth_method = context.getAuthenticationSession().getUserSessionNotes().get("psso_auth_method");
        logger.info("PSSO: User method: : " + psso_auth_method);
        logger.info("PSSO: Condition method: : " + psso_auth_method_cond);
        logger.info("PSSO: Invert condition: : " + psso_auth_method_invert);
        if (psso_auth_method != null && psso_auth_method_cond != null) {
            return psso_auth_method.equals(psso_auth_method_cond) ^ psso_auth_method_invert.equals("true");
        }
        return false;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void action(AuthenticationFlowContext afc) {
        // Not used
    }

    @Override
    public void close() {
        //  Not used
    }

    @Override
    public void setRequiredActions(KeycloakSession ks, RealmModel rm, UserModel um) {
        // Not used
    }
}
