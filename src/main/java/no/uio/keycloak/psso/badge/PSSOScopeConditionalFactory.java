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

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSOScopeConditionalFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "psso-scope-conditional";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty scope = new ProviderConfigProperty();
        scope.setName(PSSOScopeConditional.CONF_SCOPE);
        scope.setLabel("Scope");
        scope.setType(ProviderConfigProperty.STRING_TYPE);
        scope.setDefaultValue(PSSOScopeConditional.DEFAULT_SCOPE);
        scope.setHelpText("The condition is true when the authorization request's scope "
                + "parameter contains this value. Platform SSO web-based authentication adds "
                + "\"" + PSSOScopeConditional.DEFAULT_SCOPE + "\" to the scope itself.");
        configProperties.add(scope);

        ProviderConfigProperty invert = new ProviderConfigProperty();
        invert.setName(PSSOScopeConditional.CONF_INVERT);
        invert.setLabel("Invert this conditional.");
        invert.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        invert.setHelpText("If inverted, the condition is false when the scope matches.");
        configProperties.add(invert);
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public ConditionalAuthenticator getSingleton() {
        return PSSOScopeConditional.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - Platform SSO scope";
    }

    @Override
    public String getHelpText() {
        return "Matches when the authorization request asked for a given scope, for example "
                + "the scope Platform SSO adds to web-based authentication.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void init(Config.Scope config) {
        // Not used
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Not used
    }

    @Override
    public void close() {
        // Not used
    }
}
