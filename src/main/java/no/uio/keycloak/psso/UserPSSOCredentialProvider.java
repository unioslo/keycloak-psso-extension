package no.uio.keycloak.psso;


import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.*;
        import org.keycloak.models.cache.UserCache;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.keycloak.storage.UserStorageUtil.userCache;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 0
 * University of Oslo 2025
 */
public class UserPSSOCredentialProvider implements CredentialProvider<UserPSSOCredentialModel>, CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(UserPSSOCredentialProvider.class);

    protected KeycloakSession session;

    public UserPSSOCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!UserPSSOCredentialModel.TYPE.equals(credentialType)) {
            return false;
        }

        // Check only local Keycloak credentials
        return !user.credentialManager()
                .getStoredCredentialsByTypeStream(UserPSSOCredentialModel.TYPE)
                .toList()
                .isEmpty();


    }
    @Override
    public String getType() {
        return UserPSSOCredentialModel.TYPE;
    }
/*
    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel model) {
        // Register new credential in EduMFA
        String tokenId = EduMFA.enroll(user.getUsername());
        return EduMfaCredentialModel.createFromEduMfa(user.getUsername(), tokenId);
    }

 */

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {

        return user.credentialManager().removeStoredCredentialById(credentialId);
    }


    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, UserPSSOCredentialModel credential) {
        logger.info("Creating Secure enclave credential for user "+user.getUsername());
        // Persist
        user.credentialManager().createStoredCredential(credential);

        // Clear cache
        KeycloakSession session = this.session;
        UserCache userCache = session.getProvider(UserCache.class);
        if (userCache != null) {
            userCache.evict(realm, user);
        }

        return credential;
    }


    @Override
    public UserPSSOCredentialModel getCredentialFromModel(CredentialModel model) {

        if (model == null) {
            logger.info("CredentialModel passed in is null");
            return null;
        }

        UserPSSOCredentialModel userPSSOCredentialModel;
        UserPSSOCredentialData data =
                null;
        try {
            data = JsonSerialization.readValue(model.getCredentialData(), UserPSSOCredentialData.class);
        } catch (IOException e) {
            logger.error("Error reading UserPSSOCredentialData", e);
            throw new RuntimeException(e);
        }


        if (model instanceof UserPSSOCredentialModel) {
            userPSSOCredentialModel = (UserPSSOCredentialModel) model;
        } else {
            userPSSOCredentialModel = new UserPSSOCredentialModel();
            userPSSOCredentialModel.setUserSecureEnclaveKey(data.getUserSecureEnclaveKey());
            userPSSOCredentialModel.setUserKeyId(data.getUserKeyId());
            userPSSOCredentialModel.setDeviceUDID(data.getDeviceUDID());
            userPSSOCredentialModel.setSerial(data.getSerial());
            userPSSOCredentialModel.setUserLabel(data.getLabel());

            userPSSOCredentialModel.setId(model.getId());
            userPSSOCredentialModel.setUserLabel(model.getUserLabel());
            userPSSOCredentialModel.setCredentialData(model.getCredentialData());
            userPSSOCredentialModel.setCreatedDate(model.getCreatedDate());
        }

        logger.infof("CredentialModel ID: %s, Label: %s, Data: %s, Created: %s",
                userPSSOCredentialModel.getId(),
                userPSSOCredentialModel.getUserLabel(),
                userPSSOCredentialModel.getCredentialData(),
                userPSSOCredentialModel.getCreatedDate());

        return userPSSOCredentialModel;

    }


    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext ctx) {

        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("Platform SSO")
                .helpText("Single Sign-on login for macOS devices")
                .iconCssClass("kcAuthenticatorOTPClass")
            //    .createAction(EduMFARequiredAction.PROVIDER_ID)
                .removeable(true)
                .build(session);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return UserPSSOCredentialModel.TYPE.equals(credentialType);
    }


    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
        return false;
    }


}