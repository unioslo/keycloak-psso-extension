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