/* Copyright 2025 University of Oslo, Norway
 # This file is part of Cerebrum.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension  is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/
package no.uio.keycloak.psso;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "psso_device")
@NamedQueries({
        @NamedQuery(name = "Device.findByUUID",
                query = "SELECT d FROM Device d WHERE d.deviceUUID = :uuid")
})
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO) // or AUTO
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @Column(name = "realm_id", length = 36, nullable = false)
    private String realmId;

    @Column(name = "device_uuid", length = 128, nullable = false, unique = true)
    private String deviceUUID;

    @Column(name = "category", length = 64, nullable = false)
    private String category;

    @Lob
    @Column(name = "signing_key", nullable = false)
    private String signingKey;

    @Lob
    @Column(name = "encryption_key", nullable = false)
    private String encryptionKey;

    @Lob
    @Column(name = "key_exchange_key", nullable = false)
    private String keyExchangeKey;

    @Column(name = "creation_time", nullable = false)
    private long creationTime;

    public Device() {}

    public Device(String id, String realmId, String deviceUUID,
                        String category, String signingKey, String encryptionKey,
                        String keyExchangeKey, long creationTime) {
        this.id = id;
        this.realmId = realmId;
        this.deviceUUID = deviceUUID;
        this.category = category;
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        this.keyExchangeKey = keyExchangeKey;
        this.creationTime = creationTime;
    }

    // getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getDeviceUUID() { return deviceUUID; }
    public void setDeviceUUID(String deviceUUID) { this.deviceUUID = deviceUUID; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getSigningKey() { return signingKey; }
    public void setSigningKey(String signingKey) { this.signingKey = signingKey; }

    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }

    public String getKeyExchangeKey() { return keyExchangeKey; }
    public void setKeyExchangeKey(String keyExchangeKey) { this.keyExchangeKey = keyExchangeKey; }

    public long getCreationTime() { return creationTime; }
    public void setCreationTime(long creationTime) { this.creationTime = creationTime; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Device)) return false;
        Device that = (Device) o;
        return Objects.equals(deviceUUID, that.deviceUUID);
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceUUID);
    }

    @Override
    public String toString() {
        return "DeviceEntity{" +
                "deviceUUID='" + deviceUUID + '\'' +
                ", category='" + category + '\'' +
                ", creationTime=" + creationTime +
                '}';
    }
}
