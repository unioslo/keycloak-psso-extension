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
                .add()
                .property()
                .name("clientIDOIDCFlow")
                .label("Client ID for OIDC flow")
                .helpText("Client ID for OIDC flow")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("clientSecretOIDCFlow")
                .label("Client Secret for OIDC flow")
                .helpText("Client Secret for OIDC flow")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()
                .property()
                .name("clientIDforCardRegistration")
                .label("Client ID for card registration")
                .helpText("Client ID for card registration")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("psso-card")
                .add()
                .property()
                .name("caKeysForCardValidation")
                .label("CA Keys for card validation")
                .helpText("CA Keys for card validation. Users registering cards with keys will have hose validated against one of these keys. "
                        + "Paste one or more certificates as PEM, one after the other: a bundle rather than a single "
                        + "certificate so an issuer key can be rotated without every card issued under the old one "
                        + "losing the ability to enroll. Key ids are derived from the keys, never entered by hand.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name("cardSerialPrefixes")
                .label("Accepted card serial prefixes")
                .helpText("Comma-separated, e.g. \"CPLC:\". Leave empty to accept any card. "
                        + "provision-card.sh falls back to a \"SIM:\" identity when a chip reports a blank CPLC, "
                        + "so an empty list lets a simulated card enroll against a real account.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("cardEnrollMaxAgeDays")
                .label("Maximum age of a card issuance record")
                .helpText("Reject issuance records older than this many days. Signatures do not expire on their own, "
                        + "so without a bound a record for a card decommissioned two years ago stays enrollable.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("30")
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
