package no.uio.keycloak.psso;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;



public class UserPSSOCredentialProviderFactory implements CredentialProviderFactory<UserPSSOCredentialProvider> {
    public static final String PROVIDER_ID =  "psso";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new UserPSSOCredentialProvider(session);
    }

}