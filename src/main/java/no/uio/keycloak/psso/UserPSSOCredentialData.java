/* Copyright 2025 University of Oslo, Norway
 # This file is part of Cerebrum.
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

public class UserPSSOCredentialData {

    private String label;
    private String userSecureEnclaveKey;
    private String userKeyId;
    private String deviceUDID;
    private String serial;

    public UserPSSOCredentialData() {
    }

    public UserPSSOCredentialData( String label, String userSecureEnclaveKey, String userKeyId, String deviceUDID, String serial ) {
        this.userSecureEnclaveKey = userSecureEnclaveKey;
        this.label = label;
        this.deviceUDID = deviceUDID;
        this.serial = serial;
        this.userKeyId = userKeyId;


    }

    public String getUserSecureEnclaveKey() {
        return userSecureEnclaveKey;
    }
    public void setUserSecureEnclaveKey( String userSecureEnclaveKey ) {
        this.userSecureEnclaveKey = userSecureEnclaveKey;
    }

    public String getLabel() { return label; }
    public void setLabel(String label) {
        this.label = label;
    }
    public String getDeviceUDID() { return deviceUDID; }
    public void setDeviceUDID( String deviceUDID ) { this.deviceUDID = deviceUDID; }
    public String getSerial() { return serial; }
    public void setSerial( String serial ) { this.serial = serial; }
    public String getUserKeyId() { return userKeyId; }
    public void setUserKeyId(String userKeyId) { this.userKeyId = userKeyId; }
}