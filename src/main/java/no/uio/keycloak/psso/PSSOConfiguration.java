package no.uio.keycloak.psso;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.ui.extend.UiTabProvider;
import org.keycloak.services.ui.extend.UiTabProviderFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PSSOConfiguration implements UiTabProvider, UiTabProviderFactory<ComponentModel> {
    private KeycloakSession session;

    @Override
    public String getId() {
        return "Platform Single Sign-on";
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        builder.property()
                .name("requireRegistrationToken")
                .label("Require Registration Token")
                .helpText("Require Registration Token for device registration. If not required, a user token will be required.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name("registrationToken")
                .label("Registration Token")
                .helpText("Registration Token for device registration")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add();
        return builder.build();
    }

    @Override
    public String getPath() {
        return "/:realm/realm-settings/:tab";
    }

    @Override
    public Map<String, String> getParams() {
        Map<String, String> params = new HashMap<>();
        params.put("tab", "psso");
        return params;
    }

}
