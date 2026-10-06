package no.uio.keycloak.psso.kerberos;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Base64;

/**
 * A TGT in the shape Apple's Platform SSO login response expects.
 *
 * The field names emitted here are the defaults from Apple's documentation; the Mac side maps them
 * via {@code ASAuthorizationProviderExtensionKerberosMapping}, so they must match whatever the
 * companion SSO extension configures.
 */
public record KerberosTgt(
        String clientName,
        String realm,
        String serviceName,
        int encryptionKeyType,
        byte[] sessionKey,
        byte[] asRep,
        long endTimeMillis
) {

    public JSONObject toAppleDictionary() throws JSONException {
        Base64.Encoder base64 = Base64.getEncoder();
        JSONObject tgt = new JSONObject();
        tgt.put("clientName", clientName);
        tgt.put("realm", realm);
        tgt.put("serviceName", serviceName);
        // Must be a JSON number, unlike the string-valued expires_in alongside it.
        tgt.put("encryptionKeyType", encryptionKeyType);
        tgt.put("sessionKey", base64.encodeToString(sessionKey));
        tgt.put("messageBuffer", base64.encodeToString(asRep));
        return tgt;
    }
}
