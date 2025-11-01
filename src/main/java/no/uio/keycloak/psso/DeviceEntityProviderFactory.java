package no.uio.keycloak.psso;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.Set;

public class DeviceEntityProviderFactory implements JpaEntityProviderFactory {
    @Override
    public JpaEntityProvider create(KeycloakSession keycloakSession) {
        return new DeviceEntityProvider();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "psso_device";
    }

    @Override
    public int order() {
        return JpaEntityProviderFactory.super.order();
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return JpaEntityProviderFactory.super.getConfigMetadata();
    }

    @Override
    public Set<Class<? extends Provider>> dependsOn() {
        return JpaEntityProviderFactory.super.dependsOn();
    }
}
