package no.uio.keycloak.psso;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import java.util.Collections;
import java.util.List;

public class DeviceEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        return Collections.<Class<?>>singletonList(Device.class);
    }

    // This is used to return the location of the Liquibase changelog file.
    // You can return null if you don't want Liquibase to create and update the DB schema.
    @Override
    public String getChangelogLocation() {
        return "META-INF/device-entity-provider-changelog.xml";
    }

    // Helper method, which will be used internally by Liquibase.
    @Override
    public String getFactoryId() {
        return "psso_device";
    }

    @Override
    public void close() {

    }
}
