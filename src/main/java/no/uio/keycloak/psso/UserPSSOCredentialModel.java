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


import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;



public class UserPSSOCredentialModel extends CredentialModel{
    public static final String TYPE = "psso";
    private String userSecureEnclaveKey;
    private String userKeyId;
    private String deviceUDID;
    private String serial;

    public UserPSSOCredentialModel() {
        setType(TYPE);
    }

    // Example factory method if you need to wrap something from EduMFA
    public static UserPSSOCredentialModel createCredential (String userId, String userSecureEnclaveKey, String userKeyId,  String deviceUDID, String serial) {
        UserPSSOCredentialModel model = new UserPSSOCredentialModel();
        String label = "Mac serial number: " + serial;
        model.setUserLabel(label);

        try {
            UserPSSOCredentialData data = new UserPSSOCredentialData( label,userSecureEnclaveKey, userKeyId, deviceUDID, serial );

            model.setCredentialData(JsonSerialization.writeValueAsString(data));
            Long now = System.currentTimeMillis();
            model.setCreatedDate(now);
        } catch (Exception e) {
            throw new RuntimeException("Error serializing credential data", e);
        }
        // model.setCreatedDate(System.currentTimeMillis());
        // no local secretData, since EduMFA is external
        return model;
    }

    public String getUserSecureEnclaveKey() { return userSecureEnclaveKey; }
    public void setUserSecureEnclaveKey(String val) { this.userSecureEnclaveKey = val; }
    public String getUserKeyId() { return userKeyId; }
    public void setUserKeyId(String val) { this.userKeyId = val; }
    public String getDeviceUDID() { return deviceUDID; }
    public void setDeviceUDID(String val) { this.deviceUDID = val; }
    public String getSerial() { return serial; }
    public void setSerial(String val) { this.serial = val; }

    public static UserPSSOCredentialData getCredentialData(CredentialModel cm) {
        try {
            return JsonSerialization.readValue(cm.getCredentialData(), UserPSSOCredentialData.class);
        } catch (Exception e) {
            throw new RuntimeException("Error deserializing credential data", e);
        }
    }



}