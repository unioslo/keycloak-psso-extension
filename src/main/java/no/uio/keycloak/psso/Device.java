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
package no.uio.keycloak.psso;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "psso_device")
@NamedQueries({
        @NamedQuery(name = "Device.findByUDID",
                query = "SELECT d FROM Device d WHERE d.deviceUDID = :udid"),
        @NamedQuery(name = "Device.findBySerialNumber",
                query = "SELECT d FROM Device d WHERE d.serialNumber = :serialNumber"),
        @NamedQuery(name = "Device.findBySignKeyId",
                query = "SELECT d FROM Device d WHERE d.signingKeyId = :signingKeyId"),
        @NamedQuery(name = "Device.findByEncKeyId",
                query = "SELECT d FROM Device d WHERE d.encryptionKeyId = :encryptionKeyId")

})
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private Long id;

    @Column(name = "realm_id", length = 36, nullable = false)
    private String realmId;

    @Column(name = "device_udid", length = 128, nullable = false, unique = true)
    private String deviceUDID;

    @Column(name = "serial_number", length = 128, unique = true)
    private String serialNumber; // <-- new column

    @Column(name = "category", length = 64, nullable = false)
    private String category;

    @Lob
    @Column(name = "signing_key", nullable = false)
    private String signingKey;
    @Lob
    @Column(name = "signing_key_id", nullable = false)
    private String signingKeyId;

    @Lob
    @Column(name = "encryption_key", nullable = false)
    private String encryptionKey;

    @Lob
    @Column(name = "encryption_key_id", nullable = false)
    private String encryptionKeyId;

    @Lob
    @Column(name = "registered_by", nullable = false)
    private String registeredBy;

    @Lob
    @Column(name = "key_exchange_key", nullable = false)
    private String keyExchangeKey;

    @Column(name = "creation_time", nullable = false)
    private long creationTime;

    public Device() {}

    public Device(Long id, String realmId, String deviceUDID, String serialNumber,
                  String category, String signingKey, String signingKeyId,  String encryptionKey,  String encryptionKeyId,
                  String keyExchangeKey, String registeredBy, long creationTime) {
        this.id = id;
        this.realmId = realmId;
        this.deviceUDID = deviceUDID;
        this.serialNumber = serialNumber;
        this.category = category;
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        this.encryptionKeyId = encryptionKeyId;
        this.signingKeyId = signingKeyId;
        this.registeredBy = registeredBy;
        this.keyExchangeKey = keyExchangeKey;
        this.creationTime = creationTime;
    }

    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getDeviceUDID() { return deviceUDID; }
    public void setDeviceUDID(String deviceUDID) { this.deviceUDID = deviceUDID; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getSigningKey() { return signingKey; }
    public void setSigningKey(String signingKey) { this.signingKey = signingKey; }

    public String getSigningKeyId() { return signingKeyId; }
    public void setSigningKeyId(String signingKeyId) { this.signingKeyId = signingKeyId; }

    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }

    public String getEncryptionKeyId() { return encryptionKeyId; }
    public void setEncryptionKeyId(String encryptionKeyId) { this.encryptionKeyId = encryptionKeyId; }


    public String getRegisteredBy() { return registeredBy; }
    public void setRegisteredBy(String registeredBy) { this.registeredBy = registeredBy; }

    public String getKeyExchangeKey() { return keyExchangeKey; }
    public void setKeyExchangeKey(String keyExchangeKey) { this.keyExchangeKey = keyExchangeKey; }

    public long getCreationTime() { return creationTime; }
    public void setCreationTime(long creationTime) { this.creationTime = creationTime; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Device)) return false;
        Device that = (Device) o;
        return Objects.equals(deviceUDID, that.deviceUDID);
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceUDID);
    }

    @Override
    public String toString() {
        return "DeviceEntity{" +
                "deviceUUID='" + deviceUDID + '\'' +
                ", serialNumber='" + serialNumber + '\'' +
                ", category='" + category + '\'' +
                ", registeredBy='" + registeredBy + '\'' +
                ", creationTime=" + creationTime +
                '}';
    }
}
