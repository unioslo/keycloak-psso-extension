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

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;

import java.security.MessageDigest;
import java.util.List;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSOBadgeCredentialProvider
        implements CredentialProvider<PSSOBadgeCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(PSSOBadgeCredentialProvider.class);

    protected KeycloakSession session;

    public PSSOBadgeCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return PSSOBadgeCredentialModel.TYPE;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PSSOBadgeCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) {
            return false;
        }
        return !getBadges(user).isEmpty();
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PSSOBadgeCredentialModel credential) {
        logger.info("Platform SSO: creating QR badge credential for user " + user.getUsername());
        user.credentialManager().createStoredCredential(credential);

        UserCache userCache = session.getProvider(UserCache.class);
        if (userCache != null) {
            userCache.evict(realm, user);
        }

        return credential;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public PSSOBadgeCredentialModel getCredentialFromModel(CredentialModel model) {
        if (model == null) {
            logger.error("Platform SSO: CredentialModel passed in is null");
            return null;
        }
        if (model instanceof PSSOBadgeCredentialModel) {
            return (PSSOBadgeCredentialModel) model;
        }

        PSSOBadgeCredentialModel badge = new PSSOBadgeCredentialModel();
        badge.setId(model.getId());
        badge.setUserLabel(model.getUserLabel());
        badge.setCredentialData(model.getCredentialData());
        badge.setSecretData(model.getSecretData());
        badge.setCreatedDate(model.getCreatedDate());
        return badge;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext ctx) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                // A badge logs the pupil in by itself, so it is a first factor - not the
                // TWO_FACTOR category the Secure Enclave credential uses.
                .category(CredentialTypeMetadata.Category.BASIC_AUTHENTICATION)
                .displayName("Platform SSO QR badge")
                .helpText("Printed QR badge for signing in to shared Macs")
                .iconCssClass("kcAuthenticatorDefaultClass")
                // No createAction: teachers issue badges through the API, pupils do not
                // self-enrol.
                .removeable(true)
                .build(session);
    }

    /** Every badge currently issued to this user. */
    public List<CredentialModel> getBadges(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(PSSOBadgeCredentialModel.TYPE)
                .toList();
    }

    /**
     * Checks a scanned payload against the user's badges.
     *
     * <p>The payload's sequence number picks the candidate credential; only the token is
     * secret, so comparing it in constant time is what matters. Returns the matching
     * credential, or {@code null}.
     */
    public CredentialModel validateBadge(UserModel user, PSSOBadgePayload payload) {
        if (payload == null || !user.getId().equals(payload.getUserId())) {
            return null;
        }

        byte[] presented = PSSOBadgePayload.sha256(payload.getToken());

        for (CredentialModel candidate : getBadges(user)) {
            PSSOBadgeCredentialData data;
            try {
                data = PSSOBadgeCredentialModel.getCredentialData(candidate);
            } catch (RuntimeException e) {
                logger.warn("Platform SSO: unreadable badge credential " + candidate.getId()
                        + " on user " + user.getUsername() + ": " + e.getMessage());
                continue;
            }
            if (data.getBadgeSequence() != payload.getSequence()) {
                continue;
            }
            byte[] stored = PSSOBadgeCredentialModel.getStoredHash(candidate);
            if (stored != null && MessageDigest.isEqual(stored, presented)) {
                return candidate;
            }
        }
        return null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        if (credentialInput == null || !supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        // The challenge response is the whole scanned payload, prefix and all.
        return validateBadge(user, PSSOBadgePayload.parse(credentialInput.getChallengeResponse())) != null;
    }
}
