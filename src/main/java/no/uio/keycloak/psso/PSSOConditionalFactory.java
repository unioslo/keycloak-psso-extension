package no.uio.keycloak.psso;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;

public class PSSOConditionalFactory implements ConditionalAuthenticatorFactory {
    public static final String PROVIDER_ID = "psso-conditional";

    public ConditionalAuthenticator getSingleton() {
        return PSSOConditional.SINGLETON;
    }


    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {
        // Not used
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /*
    @Override
    public String getReferenceCategory() {
        return "condition";
    }

     */

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.CONDITIONAL,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Platform SSO Authentication Method conditional";
    }

    @Override
    public String getHelpText() {
        return "Conditional to be used dependant on the PSSO Authentication Method.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();


    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("psso_auth_method");
        property.setLabel("Select the PSSO Authentication Method.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(List.of("PASSWORD", "SECURE_ENCLAVE"));
        property.setHelpText("If the authentication method used by the Platform Single Sign-on was used, this conditional will be set to \"true\".");
        configProperties.add(property);
    }



    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}