package no.uio.keycloak.psso;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class PSSOResourceProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public PSSOResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new PSSOResource(session);
    }

    @Override
    public void close() {
    }
}