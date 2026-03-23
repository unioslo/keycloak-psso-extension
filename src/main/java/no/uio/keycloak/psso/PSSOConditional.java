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
        String psso_auth_method = context.getAuthenticationSession().getUserSessionNotes().get("psso_auth_method");

        if (psso_auth_method != null && psso_auth_method_cond != null) {
            return psso_auth_method.equals(psso_auth_method_cond);
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
