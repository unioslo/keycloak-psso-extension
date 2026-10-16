/* Copyright 2026 University of Oslo, Norway
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
