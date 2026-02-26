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

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import jakarta.transaction.Transactional;
import no.uio.keycloak.psso.token.*;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import no.uio.keycloak.psso.token.JWSDecoder;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;



import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.ui.extend.UiTabProvider;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.*;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
@Path("")
public class PSSOResource {

    private final KeycloakSession session;
    static Logger logger = Logger.getLogger(PSSOResource.class);

    public PSSOResource(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Path("/nonce")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNonce(
            @FormParam("grant_type") @DefaultValue("") String grantType,
            @HeaderParam("client-request-id") @DefaultValue("") String clientRequestId) {


        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent  = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");

        logger.info("Noonce request. From: " + ip_address+ ", User-Agent: " + userAgent+" Client Request ID: "+clientRequestId+ " Grant Type: "+grantType);


        if (clientRequestId == null || clientRequestId.isEmpty() || !grantType.equals("srv_challenge")) {
           String error = "Missing required parameters: grant_type, client-request-id and/or nonce";
            logger.error(error+ "From: " + ip_address+ ", User-Agent: " + userAgent+" Client Request ID: "+clientRequestId+ " Grant Type: "+grantType);

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", error))
                    .build();
        }

        NonceService nonceService = new NonceService(session);
        String nonce = nonceService.createNonce(clientRequestId);
        logger.debug("Nonce created: " + nonce);
        return Response.ok(Map.of("nonce", nonce)).build();
    }

    @POST
    @Path("/enroll")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response enroll(
            @HeaderParam("client-request-id") @DefaultValue("") String clientRequestId,
           EnrollmentRequest enrollmentRequest
            ) throws Exception {


        RealmModel realm = session.getContext().getRealm();
        ComponentModel pssoConfig = realm.getComponentsStream(realm.getId(), UiTabProvider.class.getName())
                .filter(c -> "Platform Single Sign-on".equals(c.getProviderId()))
                .findFirst()
                .orElse(null);

        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent  = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");

        if  (pssoConfig == null) {
            logger.error("No PSSO configuration found for realm: " + realm.getId());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        boolean registrationTokenRequired = pssoConfig.getConfig().getFirst("requireRegistrationToken").equals("true");
        String savedRegistrationToken = pssoConfig.getConfig().getFirst("registrationToken");



        logger.info("Enroll device request. From: " + ip_address+ ", User-Agent: " + userAgent+" Client Request ID: "+clientRequestId);
        String deviceSigningKey = enrollmentRequest.DeviceSigningKey;
        String deviceEncryptionKey = enrollmentRequest.DeviceEncryptionKey;
        String signKeyID = enrollmentRequest.SignKeyID;
        String encKeyID = enrollmentRequest.EncKeyID;
        List<String> attestationJsonB64Array = enrollmentRequest.attestation;
        String nonce = enrollmentRequest.nonce;
        String accessToken = enrollmentRequest.accessToken;
        String registrationToken = enrollmentRequest.registrationToken;
        AccessToken token;

        if (registrationTokenRequired && (savedRegistrationToken.isEmpty() || registrationToken == null || registrationToken.isEmpty() || !registrationToken.equals(savedRegistrationToken))) {
            logger.error("Platform SSO: Registration token not saved, is empty or there is a wrong one.");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        String registeredBy;

        if (registrationTokenRequired) {
            registeredBy = "registrationToken";
        } else {
            try {
                token = new AccessTokenValidator(session)
                        .validate(accessToken, "psso");   // expectedClient may be null if you don’t need it
            } catch (Exception e) {
                logger.error("Platform SSO: Error validating access token: " + e.getMessage());
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            registeredBy = token.getPreferredUsername();
        }

        SecureRandom random = new SecureRandom();
        byte[] keyExchangeKeyBytes = new byte[32];
        random.nextBytes(keyExchangeKeyBytes);

        String keyExchangeKey = Base64.getEncoder().encodeToString(keyExchangeKeyBytes);
        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();

        // TODO: check if device already exists
        // TODO: authenticate the device to check if it exists on the MDM or is legit

        // For example: check with the Apple Root CA
        X509Certificate appleRoot = AppleRootCertLoader.loadAppleRootCert("/apple_cert/Apple_Enterprise_Attestation_Root_CA.pem");
        AppleAttestationVerifier verifier = new AppleAttestationVerifier(appleRoot);
        boolean isAttested = verifier.verifyAppleAttestation(attestationJsonB64Array, deviceSigningKey, nonce, session, clientRequestId);
        DeviceAttestationObject deviceAttestationObject = verifier.deviceAttestationObject;
        String serial = deviceAttestationObject.getSerial();
        String deviceUDID = deviceAttestationObject.getDeviceUDid();
        Device existingDevice = null;
        try {
            existingDevice = em.createNamedQuery("Device.findByUDID", Device.class)
                    .setParameter("udid", deviceUDID)
                    .getSingleResult();
        } catch (NoResultException e) {
            logger.error("No existing device found for UDID: " + deviceUDID+". Creating a new one.");
            // no existing device
        }

        if (existingDevice != null) {
            logger.info("Updating existing device with serial number: " + serial+ ". Registered by user: " + registeredBy);
            existingDevice.setSigningKey(deviceSigningKey);
            existingDevice.setEncryptionKey(deviceEncryptionKey);
            existingDevice.setKeyExchangeKey(keyExchangeKey);
            existingDevice.setSerialNumber(serial);
            existingDevice.setCategory("psso-mac");
            existingDevice.setCreationTime(System.currentTimeMillis());
            existingDevice.setRegisteredBy(registeredBy);
            existingDevice.setEncryptionKeyId(encKeyID);
            existingDevice.setSigningKeyId(signKeyID);
            em.merge(existingDevice);
        } else {
            logger.info("Registering new device with serial number: " + serial + ". Registered by user: " + registeredBy);
            Device device = new Device();
            device.setDeviceUDID(deviceUDID);
            device.setSerialNumber(serial);
            device.setSigningKey(deviceSigningKey);
            device.setEncryptionKey(deviceEncryptionKey);
            device.setKeyExchangeKey(keyExchangeKey);
            device.setRealmId(session.getContext().getRealm().getId());
            device.setCategory("psso-mac");
            device.setCreationTime(System.currentTimeMillis());
            device.setRegisteredBy(registeredBy);
            device.setEncryptionKeyId(encKeyID);
            device.setSigningKeyId(signKeyID);
            em.persist(device);
        }



        return Response.ok(Map.of("status", "OK")).build();
    }


    @POST
    @Path("/userenroll")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response userEnroll(
            @HeaderParam("client-request-id") @DefaultValue("") String clientRequestId,
            UserEnrollmentRequest enrollmentRequest
    ) throws Exception {


        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("Enroll user request. From: " + ip_address + ", User-Agent: " + userAgent + " Client Request ID: " + clientRequestId);
        List<String> attestationJsonB64Array = enrollmentRequest.attestation;
        String nonce = enrollmentRequest.nonce;
        String accessToken = enrollmentRequest.accessToken;
        String userKey = enrollmentRequest.userKey;
        String userKeyId = enrollmentRequest.userKeyId;
        X509Certificate appleRoot = AppleRootCertLoader.loadAppleRootCert("/apple_cert/Apple_Enterprise_Attestation_Root_CA.pem");

        AppleAttestationVerifier verifier = new AppleAttestationVerifier(appleRoot);
        boolean isAttested = verifier.verifyAppleAttestation(attestationJsonB64Array, userKey, nonce, session, clientRequestId);
        DeviceAttestationObject deviceAttestationObject = verifier.deviceAttestationObject;

        AccessToken token;
        try {
            token = new AccessTokenValidator(session)
                    .validate(accessToken, "psso");   // expectedClient may be null if you don’t need it
        }catch (Exception e) {
            logger.error("Error validating access token: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        String username = token.getPreferredUsername();
        // Verify if the device exists
        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();
        String deviceUDID = deviceAttestationObject.getDeviceUDid();
        String serial =  deviceAttestationObject.getSerial();
        Device existingDevice = null;
        try {
            existingDevice = em.createNamedQuery("Device.findByUDID", Device.class)
                    .setParameter("udid", deviceUDID)
                    .getSingleResult();
        } catch (NoResultException e) {
            logger.error("No existing device found for UDID: " + deviceUDID+". The user is registering for a non existing device.");
            return Response.status(Response.Status.UNAUTHORIZED).build();
            // no existing device
        }

        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, token.getSubject());
        if (user == null) {
            logger.error("User not found: " + token.getSubject());
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        // Check if the user already have a credential for this machine
        List<CredentialModel> credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(UserPSSOCredentialModel.TYPE)
                .toList();
        logger.debug("Found "+credentials.size()+" existing credentials for user "+user.getUsername());

        for (CredentialModel existingCred : credentials) {
            String id = existingCred.getId();
            UserPSSOCredentialData credData = UserPSSOCredentialModel.getCredentialData(existingCred);
            String currentSerial = credData.getSerial();
            if (serial.equals(currentSerial)) {
                user.credentialManager().removeStoredCredentialById(id);
            }
        }

        UserPSSOCredentialModel model = UserPSSOCredentialModel.createCredential(username, userKey, userKeyId, deviceUDID, serial );
        user.credentialManager().createStoredCredential(model);
        logger.info ("Platform SSO: User: "+username+ " successfully registered for device: "+serial);
        return Response.ok(Map.of("status", "OK")).build();

    }

    @POST
    @Path("/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/platformsso-login-response+jwt")
    public Response token(@FormParam("platform_sso_version") String version,
                          @FormParam("grant_type") String grantType,
                          @FormParam("assertion") String assertion,
                          @FormParam("request") String requestParam /* older param name */,
                          @HeaderParam("client-request-id") String clientRequestId,
                          @Context HttpHeaders headers) {
        // 1) normalize param: assertion or request
        String jwsCompact = assertion != null ? assertion : requestParam;

        String header = session.getContext().getRequestHeaders().getHeaderString("client-request-id");
        JWSDecoder jwsDecoder = new JWSDecoder(session);
        Map<String,Object> claims;
        try {
            claims = jwsDecoder.parseAndVerify(jwsCompact);
            for(Map.Entry<String, Object> claim : claims.entrySet()) {
                logger.debug(claim.getKey() + ": " + claim.getValue());
            }

        } catch (Exception e) {
            logger.error("Error parsing JWS compact claims: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/platformsso-login-response+jwt")
                    .build();
            // return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();
        String deviceKey = jwsDecoder.getKid();
        Device device;
        try {
            device = em.createNamedQuery("Device.findBySignKeyId", Device.class)
                    .setParameter("signingKeyId", deviceKey)
                    .getSingleResult();
        } catch (Exception e) {
            logger.error("Error finding device by signingKeyId: " + deviceKey+"- "+ e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }
        RealmModel realm = session.getContext().getRealm();
        String baseUrl = session.getContext().getUri().getBaseUri().toString();
        baseUrl = baseUrl.replaceAll("/$", "");
        String realmName = realm.getName();
        String issuer = "psso";
        String audience = baseUrl + "/realms/" + realmName + "/" + issuer+"/token";
        logger.debug("The calculated assertion on my instance is: "+audience);
        logger.debug("The audience on the assertion is: "+claims.get("aud"));
        try {
            AssertionValidator validator = new AssertionValidator(session);
            device = validator.validate(claims, device, audience,issuer, clientRequestId);

        } catch (Exception e) {
            logger.error("Error validating device: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }
        String sub = claims.get("sub").toString();
        UserModel user = session.users().getUserByUsername(realm, sub);
        String deviceUDID = device.getDeviceUDID();
        TokenIssuer tokenIssuer = new TokenIssuer(session);

        String refreshToken;
        Map<String,Object> assertionClaims;
        // Never happens in Secure Enclave authentication.
        // Will be used if we implement other types of authentication methods
        if (claims.get("grant_type").toString().equals("refresh_token")) {
            logger.info("Platform SSO: Refresh token request received for user "+sub);
            refreshToken = claims.get("refresh_token").toString();
            RefreshTokenValidator refreshTokenValidator = new RefreshTokenValidator(session);

            try {
                refreshTokenValidator.validate(refreshToken, "psso");
                tokenIssuer.setRefreshToken(refreshToken);
            } catch (Exception e) {
                logger.error("Error validating refresh token: " + e.getMessage());
                Response response = Response.status(Response.Status.UNAUTHORIZED).build();
            }
        }else {
            logger.info("Platform SSO: Token request received for user "+sub);
            String embeddedAssertions = claims.get("assertion").toString();

            try {

                assertionClaims = jwsDecoder.parseEmbeddedAssertion(embeddedAssertions, user, deviceUDID);
                AssertionValidator validator = new AssertionValidator(session);
                validator.validateEmbeddedAssertion(claims,assertionClaims, user.getUsername());

            } catch (Exception e) {
                logger.error("Error parsing the Embedded assertion: " + e.getMessage());
                return Response.status(Response.Status.UNAUTHORIZED)
                        .type("application/platformsso-login-response+jwt")
                        .build();
            }
        }
        String nonce = claims.get("nonce").toString();
        ClientModel client = session.clients().getClientByClientId(realm,"psso");
        EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
        Set<String> clientScopeIds = client.getClientScopes(true).keySet();
        //
        // logger.debug("Client scope IDs: " + clientScopeIds);
        IssuedTokens tokens = tokenIssuer.issueSignedTokens(realm,user, client, "openid offline_access urn:apple:platformsso groups", event, nonce, false, device);

        for (String claim : claims.keySet()) {
            logger.debug("Request claim: "+ claim +": " + claims.get(claim));
        }

        Map<String, Object> jweCrypto = (Map<String, Object>) claims.get("jwe_crypto");
        String apv = (String) jweCrypto.get("apv");

        // "Apple" is the apu encoded here as a base64 url

        byte[] apvBytes = apv != null ? Base64URL.from(apv).decode() : null;
        ECKey deviceKeyEC;
        String jwe;
        ECPublicKey deviceKeyECPublicKey;

        RefreshToken refreshTokenObject = tokens.refreshTokenObject;
        String refreshExpiresIn = refreshTokenObject.getType().equals("Offline") ? null : String.valueOf(tokenIssuer.refreshExpiresIn);
        String expiresIn = String.valueOf(tokenIssuer.expiresIn);



        try {
          deviceKeyECPublicKey = jwsDecoder.convertX963ToECPublicKey(device.getEncryptionKey());
            deviceKeyEC = new ECKey.Builder(
                    Curve.P_256,
                    deviceKeyECPublicKey
            ).keyID(device.getEncryptionKeyId())
                    .build();

            jwe = JweBuilder.buildPlatformSsoJwe(
                    deviceKeyEC,
                    apvBytes,
                    tokens.idToken,
                    tokens.refreshToken,
                    expiresIn,
                    refreshExpiresIn,
                    "platformsso-login-response+jwt"
            );
            JWEObject parsed = JWEObject.parse(jwe);
            logger.info("Platform SSO: User: "+sub+" on device: "+device.getSerialNumber()+" got an SSO token.");
            return Response.ok()
                    .type("application/platformsso-login-response+jwt")
                    .entity(jwe)
                    .build();
         } catch ( Exception e)
        {
            logger.error("Error Creating the JWE: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }


    }


    @GET
    @Path("/device")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDevices(
            @HeaderParam("Authorization") @DefaultValue("") String authorization

    ) throws Exception {


        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("List of devices requested from: " + ip_address + ", User-Agent: " + userAgent);
        AuthenticationManager.AuthResult authResult =
                new AppAuthManager.BearerTokenAuthenticator(session)
                        .authenticate();

        if (authResult == null) {
            logger.error("Platform SSO: Attempt to list devices failed. Authentication Failed");
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        AccessToken token = authResult.token();

        if ((token.getResourceAccess("psso-admin") == null) ||  !token.getResourceAccess("psso-admin")
                .isUserInRole("mac-admin")) {
            logger.error("Platform SSO: Attempt to list devices failed. Insufficient rights to do this.");

            return Response.status(Response.Status.FORBIDDEN).build();
        }
        String username = token.getPreferredUsername();
        // Verify if the device exists
        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();

        List<Device> existingDevices = em.createNamedQuery("Device.findAll", Device.class)
                .getResultList();
        logger.info("Platform SSO: Device list queried by User: " + username + ". Returned " + existingDevices.size() + " devices.");

        return Response.ok(existingDevices).build();

    }

    @GET
    @Path("/device/{serial}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDevice(
            @HeaderParam("Authorization") @DefaultValue("") String authorization,
            @PathParam("serial")  String serial

    ) throws Exception {


        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("List of devices requested from: " + ip_address + ", User-Agent: " + userAgent);
        AuthenticationManager.AuthResult authResult =
                new AppAuthManager.BearerTokenAuthenticator(session)
                        .authenticate();

        if (authResult == null) {
            logger.error("Platform SSO: Attempt to list devices failed. Authentication Failed");
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        AccessToken token = authResult.token();

        if ((token.getResourceAccess("psso-admin") == null) ||  !token.getResourceAccess("psso-admin")
                .isUserInRole("mac-admin")) {
            logger.error("Platform SSO: Attempt to list devices failed. Insufficient rights to do this.");

            return Response.status(Response.Status.FORBIDDEN).build();
        }

        if (serial == null){
            logger.error("Platform SSO: Attempt to query a device failed. No serial was sent.");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        String username = token.getPreferredUsername();
        // Verify if the device exists
        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();
        Device device;
        try {
            logger.info("Platform SSO: Device list queried by User: " + username + ". Serial number: " + serial);

            device = em.createNamedQuery("Device.findBySerialNumber", Device.class)
                    .setParameter("serialNumber", serial)
                    .getSingleResult();
        } catch (Exception e) {
            logger.error("Platform SSO: Error finding device by serial number: " + serial+"- "+ e.getMessage());
            return Response.status(Response.Status.NOT_FOUND)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }
        return Response.ok(device).build();

    }
    @DELETE
    @Path("/device/{serial}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteDevice(
            @HeaderParam("Authorization") @DefaultValue("") String authorization,
            @PathParam("serial")  String serial

    ) throws Exception {


        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("Delete device requested from: " + ip_address + ", User-Agent: " + userAgent);
        AuthenticationManager.AuthResult authResult =
                new AppAuthManager.BearerTokenAuthenticator(session)
                        .authenticate();

        if (authResult == null) {
            logger.error("Platform SSO: Attempt to delete device failed. Authentication Failed");
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        AccessToken token = authResult.token();

        if ((token.getResourceAccess("psso-admin") == null) ||  !token.getResourceAccess("psso-admin")
                .isUserInRole("mac-admin")) {
            logger.error("Platform SSO: Attempt to delete failed. Insufficient rights to do this.");

            return Response.status(Response.Status.FORBIDDEN).build();
        }

        if (serial == null){
            logger.error("Platform SSO: Attempt to delete a device failed. No serial was sent.");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        String username = token.getPreferredUsername();
        // Verify if the device exists
        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();
        Device device;
        try {
            logger.info("Platform SSO: Device deletion attempted  by User: " + username + ". Serial number: " + serial);

            device = em.createNamedQuery("Device.findBySerialNumber", Device.class)
                    .setParameter("serialNumber", serial)
                    .getSingleResult();
        } catch (Exception e) {
            logger.error("Platform SSO: Error finding device by serial number: " + serial+"- "+ e.getMessage());
            return Response.status(Response.Status.NOT_FOUND)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }
        em.remove(device);

        logger.info("Platform SSO: Device deleted. Serial number: " + serial);

        return Response.ok(device).build();

    }

}
