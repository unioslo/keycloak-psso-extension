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

package no.uio.keycloak.psso.badge;

import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.util.Base64;

/**
 * A printed QR badge, as stored on a user.
 *
 * <p>This is deliberately a credential type of its own rather than another {@code credType}
 * under {@code psso}: {@code CredentialProvider.getType()} is what the consoles and
 * {@code credentialManager().isValid()} dispatch on, so folding badges in would make them
 * indistinguishable from Secure Enclave keys in the UI, and deleting "the psso credential"
 * would take those keys out too.
 *
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSOBadgeCredentialModel extends CredentialModel {

    public static final String TYPE = "psso-badge";

    public PSSOBadgeCredentialModel() {
        setType(TYPE);
    }

    /**
     * Builds a badge credential from a freshly generated token. Only the hash is kept: the
     * caller is responsible for handing the plaintext token to the issuer once and then
     * dropping it.
     */
    public static PSSOBadgeCredentialModel createCredential(int badgeSequence, String token, String issuedBy) {
        PSSOBadgeCredentialModel model = new PSSOBadgeCredentialModel();
        String label = "QR badge #" + badgeSequence;
        model.setUserLabel(label);

        try {
            model.setCredentialData(JsonSerialization.writeValueAsString(
                    new PSSOBadgeCredentialData(label, badgeSequence, issuedBy)));
            model.setSecretData(JsonSerialization.writeValueAsString(
                    new PSSOBadgeSecretData(PSSOBadgePayload.hashToken(token))));
        } catch (Exception e) {
            throw new RuntimeException("Error serializing badge credential data", e);
        }

        model.setCreatedDate(System.currentTimeMillis());
        return model;
    }

    public static PSSOBadgeCredentialData getCredentialData(CredentialModel cm) {
        try {
            return JsonSerialization.readValue(cm.getCredentialData(), PSSOBadgeCredentialData.class);
        } catch (Exception e) {
            throw new RuntimeException("Error deserializing badge credential data", e);
        }
    }

    /**
     * The stored SHA-256 as raw bytes, ready for {@code MessageDigest.isEqual}, or
     * {@code null} if this credential has no usable secret.
     */
    public static byte[] getStoredHash(CredentialModel cm) {
        try {
            PSSOBadgeSecretData secret =
                    JsonSerialization.readValue(cm.getSecretData(), PSSOBadgeSecretData.class);
            if (secret == null || secret.getHash() == null) {
                return null;
            }
            return Base64.getDecoder().decode(secret.getHash());
        } catch (Exception e) {
            return null;
        }
    }
}
