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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import jakarta.transaction.Transactional;
import no.uio.keycloak.psso.token.*;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import no.uio.keycloak.psso.token.JWSDecoder;
import org.infinispan.functional.impl.Params;
import org.jboss.logging.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;


import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.ui.extend.UiTabProvider;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.*;

import static no.uio.keycloak.psso.PSSOAuthenticator.loadPlatformSSOPublicKey;
import static no.uio.keycloak.psso.token.JweBuilder.jsonObjectToMap;

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
            logger.error("No PSSO configuration found for realm: " + realm.getId()+". Consider enabling the Declarative UI feature.");
          //  return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        boolean registrationTokenRequired = pssoConfig != null ? pssoConfig.getConfig().getFirst("requireRegistrationToken").equals("true") : false;
        String savedRegistrationToken = pssoConfig != null ? pssoConfig.getConfig().getFirst("registrationToken") : "";



        logger.info("Enroll device request. From: " + ip_address+ ", User-Agent: " + userAgent+" Client Request ID: "+clientRequestId);
        String deviceSigningKey = enrollmentRequest.DeviceSigningKey;
        String deviceEncryptionKey = enrollmentRequest.DeviceEncryptionKey;
        String signKeyID = enrollmentRequest.SignKeyID;
        String encKeyID = enrollmentRequest.EncKeyID;
        List<String> attestationJsonB64Array = enrollmentRequest.attestation;
        String nonce = enrollmentRequest.nonce;
        String accessToken = enrollmentRequest.accessToken;
        String registrationToken = enrollmentRequest.registrationToken;
        String registrationMethodRequest = enrollmentRequest.registrationMethod;
        AccessToken token;

        RegistrationMethod registrationMethod = RegistrationMethod.valueOf(registrationMethodRequest);

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
            // Apple sends the same context if re-registering, so we need to keep the old key.
            // But if it doesn't exist, we register it. 
            if (existingDevice.getKeyExchangeKey() == null || existingDevice.getKeyExchangeKey().isEmpty()) {
                existingDevice.setKeyExchangeKey(keyExchangeKey);
            }
            existingDevice.setSerialNumber(serial);
            existingDevice.setCategory("psso-mac");
            existingDevice.setCreationTime(System.currentTimeMillis());
            existingDevice.setRegisteredBy(registeredBy);
            existingDevice.setEncryptionKeyId(encKeyID);
            existingDevice.setSigningKeyId(signKeyID);
            existingDevice.setRegistrationMethod(registrationMethod);
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
            device.setRegistrationMethod(registrationMethod);
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
    @Path("/cardenroll")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response cardEnroll(
            @HeaderParam("client-request-id") @DefaultValue("") String clientRequestId,
            @FormParam("nonce") @DefaultValue("") String nonce,
            @FormParam("accessToken") String accessToken,
            @FormParam("userKey") String userKey,
            @FormParam("userKeyId") String userKeyId,
            @FormParam("cardSerial") String deviceUDID,
            // new: the remaining inputs to the issuer's signed statement
            @FormParam("issuedAt") String issuedAt,
            @FormParam("generation") String generation,
            @FormParam("issuerSignature") String issuerSignature,
            @FormParam("issuerKeyId") String issuerKeyId
    ) throws Exception {

        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("PlatformSSO: Enroll user request. From: " + ip_address + ", User-Agent: " + userAgent + " Client Request ID: " + clientRequestId);

        RealmModel realm = session.getContext().getRealm();
        ComponentModel pssoConfig = realm.getComponentsStream(realm.getId(), UiTabProvider.class.getName())
                .filter(c -> "Platform Single Sign-on".equals(c.getProviderId()))
                .findFirst()
                .orElse(null);
        if (pssoConfig == null) {
            logger.error("PlatformSSO: No Platform Single Sign-on configuration found");
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String clientID = pssoConfig.get("clientIDforCardRegistration");
        if (clientID == null || clientID.isBlank()) {
            logger.error("PlatformSSO: clientIDforCardRegistration is not set: refusing card enrollment");
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
        }

        AccessToken token;
        try {
            // psso-card, not psso: /cardenroll plants a durable login credential, so a
            // token leaked from an ordinary PSSO login must not be enough to drive it.
            token = new AccessTokenValidator(session)
                    .validate(accessToken, clientID);
        } catch (Exception e) {
            logger.error("PlatformSSO: Error validating access token: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        // <-- your nonce validation, unchanged

        // Fresh authentication. enroll-card.py asks for it with prompt=login and
        // max_age=0, but those are requests to the server, not guarantees to us, so
        // the check belongs here. Accessor is getAuthTime() on newer Keycloak.
        Long authTime = token.getAuth_time();
        if (authTime == null || authTime <= 0 || Time.currentTime() - authTime > 300) {
            logger.warn("PlatformSSO: Rejected enrollment: authentication is stale (auth_time " + authTime + ")");
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        String username = token.getPreferredUsername();


        UserModel user = session.users().getUserById(realm, token.getSubject());
        if (user == null) {
            logger.error("PlatformSSO: User not found: " + token.getSubject());
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        // Provenance, before anything is stored. Note user.getUsername() rather than a
        // request parameter: the statement was signed for a specific person, and
        // rebuilding it from the token is what binds the two.
        CardEnrollmentValidator.Result check;
        try {
            check = CardEnrollmentValidator.forConfig(pssoConfig)
                    .validate(user.getUsername(), deviceUDID, userKey,
                            userKeyId, issuedAt, generation,
                            issuerSignature, issuerKeyId);
        } catch (Exception e) {
            logger.error("PlatformSSO: Card enrollment is not configured: " + e.getMessage());
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
        }
        if (!check.ok) {
            logger.warn("PlatformSSO: Rejected enrollment for " + user.getUsername()
                    + " (card " + deviceUDID + "): " + check.reason);
            return Response.status(Response.Status.FORBIDDEN).build();
        }
        logger.info("PlatformSSO: Card enrollment accepted for " + user.getUsername()
                + ": card " + deviceUDID + " generation " + generation
                + " key " + check.point);

        String serial = "Card: " + deviceUDID;

        // Unchanged from here down.
        List<CredentialModel> credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(UserPSSOCredentialModel.TYPE)
                .toList();
        logger.debug("PlatformSSO: Found " + credentials.size() + " existing credentials for user " + user.getUsername());

        for (CredentialModel existingCred : credentials) {
            String id = existingCred.getId();
            UserPSSOCredentialData credData = UserPSSOCredentialModel.getCredentialData(existingCred);
            String currentSerial = credData.getDeviceUDID();
            if (deviceUDID.equals(currentSerial)) {
                user.credentialManager().removeStoredCredentialById(id);
            }
        }

        UserPSSOCredentialModel model = UserPSSOCredentialModel.createCredential(username, userKey, userKeyId, deviceUDID, serial);
        user.credentialManager().createStoredCredential(model);
        logger.info("Platform SSO: User: " + username + " successfully registered a card for Tap to login: Serial: " + serial);
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

        logger.debug("Platform SSO: Received a request on /token endpoint");
        logger.info("Platform SSO: Grant type on the token request: " + grantType);
        // 1) normalize param: assertion or request
        String jwsCompact = assertion != null ? assertion : requestParam;

        String header = session.getContext().getRequestHeaders().getHeaderString("client-request-id");
        JWSDecoder jwsDecoder = new JWSDecoder(session);

        Map<String,Object> claims;
        try {
            claims = jwsDecoder.parseAndVerify(jwsCompact);
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
        boolean isRefreshTokenGrant = false;
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
        try {
            AssertionValidator validator = new AssertionValidator(session);
            device = validator.validate(claims, device, audience,issuer, clientRequestId);

        } catch (Exception e) {
            logger.error("Error validating device: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }

        String sub = claims.get("sub") != null ? claims.get("sub").toString() : null;
        UserModel user = session.users().getUserByUsername(realm, sub);
        String deviceUDID = device.getDeviceUDID();
        TokenIssuer tokenIssuer = new TokenIssuer(session);
        boolean isKeyExchange = claims.containsKey("request_type");
        boolean isGrantType = claims.containsKey("grant_type");
        String refreshTokenString;
        Map<String,Object> assertionClaims;

        // Never happens in Secure Enclave authentication.
        // Will be used if we implement other types of authentication methods
        if (isGrantType && claims.get("grant_type").toString().equals("refresh_token")) {
            isRefreshTokenGrant = true;
            refreshTokenString = claims.get("refresh_token").toString();
            RefreshTokenValidator refreshTokenValidator = new RefreshTokenValidator(session);
            try {
                RefreshToken refreshToken =  refreshTokenValidator.validate(refreshTokenString, "psso");
                tokenIssuer.setRefreshToken(refreshTokenString);
                user = session.users().getUserById(realm, refreshToken.getSubject() );
                logger.info("Platform SSO: Refresh token grant type requested by user "+sub);

            } catch (Exception e) {
                logger.error("Error validating refresh token: " + e.getMessage());
                Response response = Response.status(Response.Status.UNAUTHORIZED).build();
            }
        }else if (isGrantType && claims.get("grant_type").toString().equals("urn:ietf:params:oauth:grant-type:jwt-bearer")) {
            logger.info("Platform SSO: Token request received for user "+sub+" with grant type: "+grantType);
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
        } else if (isGrantType && claims.get("grant_type").toString().equals("urn:ietf:params:oauth:grant-type:token-exchange")) {
            logger.info("Platform SSO: OIDC flow starded for user "+sub);
            String subjectToken = claims.get("subject_token").toString();
            try {
                URI uri = new URI(subjectToken);
                String scheme = uri.getScheme();
                Map<String,String> params = PSSOUtils.parseQueryParams(uri.getQuery());
                String code = params.get("code");
                String state = params.get("state");

                EventBuilder event = new EventBuilder(
                        session.getContext().getRealm(),
                        session,
                        session.getContext().getConnection()
                );
                event.event(EventType.CODE_TO_TOKEN);
                OAuth2CodeParser.ParseResult parseResult =
                        OAuth2CodeParser.parseCode(
                                session,
                                code,
                                session.getContext().getRealm(),
                                event  // event builder, optional
                        );
                if (parseResult.isIllegalCode() || parseResult.isExpiredCode()) {

                    return Response.status(400).entity("Platform SSO: Invalid or expired code").build();
                }
                AuthenticatedClientSessionModel clientSession = parseResult.getClientSession();
                ClientModel client = clientSession.getClient();
                UserSessionModel userSession = clientSession.getUserSession();
                UserModel userInRequest = userSession.getUser();
                String clientId = client.getClientId();

                ComponentModel pssoConfig = realm.getComponentsStream(realm.getId(), UiTabProvider.class.getName())
                        .filter(c -> "Platform Single Sign-on".equals(c.getProviderId()))
                        .findFirst()
                        .orElse(null);
                if (pssoConfig == null){
                    return Response.status(Response.Status.NOT_FOUND)
                            .type("application/platformsso-login-response+jwt")
                            .build();
                }

                String configuredClientId = pssoConfig.get("clientIDOIDCFlow");

                // Checks for the validity of the code

                NonceService nonceValidator = new NonceService(session);

                boolean nonceValid = nonceValidator.validateNonce(parseResult.getCodeData().getNonce(), state);
                boolean userMatches = userInRequest.getUsername().equals(user.getUsername());
                boolean clientIdMatches = clientId.equals(configuredClientId);
                boolean schemeMatches = scheme.equals("com.apple.platformsso");
                String scopes = parseResult.getCodeData().getScope();
               // logger.debug("Platform SSO: STATE: SSO token: " + state);
                //logger.debug("Platform SSO: Nonce valid: " + nonceValid);
                //logger.info("Platform SSO: User matches: " + userMatches);
                //logger.info("Platform SSO: Client ID matches: " + clientIdMatches);
                //logger.info("Platform SSO: Scheme matches: " + schemeMatches);
                //logger.info("Platform SSO: Validating the code for user: "+sub+" with scopes: "+scopes);

                if (!nonceValid || !userMatches || !clientIdMatches || !schemeMatches ) {
                    logger.error("Platform SSO: Invalid code");
                    return Response.status(400).entity("Platform SSO: Invalid or expired code").build();
                }

            } catch (Exception e) {
                logger.error("Error parsing the Embedded assertion or other authentication: " + e.getMessage());
                return Response.status(Response.Status.UNAUTHORIZED)
                        .type("application/platformsso-login-response+jwt")
                        .build();
            }

        }

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



        String nonce = claims.get("nonce").toString();

        JSONObject body = new JSONObject();
        Payload payload = null;
        String typeHeaderValue = "";

        if (isKeyExchange) {
            typeHeaderValue = "platformsso-key-response+jwt";
            logger.info("Platform SSO: Key request received for user "+sub+" of type "+claims.get("request_type").toString());
            if (claims.get("request_type").toString().equals("key_request")) {
                payload = KeyExchangeUtils.keyRequestResponse(device, sub);
            } else if (claims.get("request_type").toString().equals("key_exchange")) {
                logger.info("Platform SSO: Key exchange received for user "+sub);
                String otherPublicKey = claims.get("other_publickey").toString();
                String keyContext = claims.get("key_context").toString();
                payload = KeyExchangeUtils.keyExchangeResponse(
                        device,
                        otherPublicKey,
                        keyContext
                );
            }

        } else {

            ClientModel client = session.clients().getClientByClientId(realm, "psso");
            EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
            Set<String> clientScopeIds = client.getClientScopes(true).keySet();
            //
            IssuedTokens tokens = tokenIssuer.issueSignedTokens(realm, user, client, "openid offline_access urn:apple:platformsso groups", event, nonce, isRefreshTokenGrant, device);
            RefreshToken refreshTokenObject = tokens.refreshTokenObject;
            String refreshExpiresIn = refreshTokenObject.getType().equals("Offline") ? null : String.valueOf(tokenIssuer.refreshExpiresIn);
            String expiresIn = String.valueOf(tokenIssuer.expiresIn);
            try {
                body.put("id_token", tokens.idToken);
                body.put("refresh_token", tokens.refreshToken);
                if (expiresIn != null) body.put("expires_in", expiresIn);
                if (refreshExpiresIn != null) body.put("refresh_token_expires_in", refreshExpiresIn);
                body.put("token_type", "Bearer");
                payload = new Payload(jsonObjectToMap(body));
                typeHeaderValue = "platformsso-login-response+jwt";

            } catch (JSONException e) {
               logger.error("Error Creating the JWE: " + e.getMessage());
               return Response.status(Response.Status.UNAUTHORIZED)
                       .type("application/"+typeHeaderValue)
                       .build();
            }
        }
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
                    payload,
                    typeHeaderValue
            );
            JWEObject parsed = JWEObject.parse(jwe);
            logger.info("Platform SSO: User: "+user.getUsername()+" on device: "+device.getSerialNumber()+" got an SSO token.");
            return Response.ok()
                    .type("application/"+typeHeaderValue)
                    .entity(jwe)
                    .build();
         } catch ( Exception e)
        {
            logger.error("Error Creating the JWE: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/"+typeHeaderValue)
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

    @POST
    @Path("/authoidc")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthOidc(
            String body,
            @HeaderParam("client-request-id") @DefaultValue("") String clientRequestId,
            @QueryParam("login_hint") @DefaultValue ("") String loginHint



    ) throws Exception {
        KeycloakContext context = session.getContext();
        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("Platform SSO: Get authentication oidc start from: " + ip_address + ", User-Agent: " + userAgent + " for user " + loginHint);

        String request = body.replaceFirst("^[Rr]equest=+", "");
        String state;
        String nonce;
        String clientId;
        String scope;
        try {

            SignedJWT jwt = SignedJWT.parse(request);
            String kid = jwt.getHeader().getKeyID();

            // Claims (the request data)
            var claims = jwt.getJWTClaimsSet();
            clientId = claims.getStringClaim("client_id");
            scope    = claims.getStringClaim("scope");
            state    = claims.getStringClaim("state");
            nonce    = claims.getStringClaim("nonce");

            Device device;
            try {
                JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
                EntityManager em = jpa.getEntityManager();

                device = em.createNamedQuery("Device.findBySignKeyId", Device.class)
                        .setParameter("signingKeyId", kid)
                        .getSingleResult();
                if (device != null){
                    logger.info("Platform SSO: Device found. Checking signature.");
                } else {
                    logger.error("Platform SSO: Device not found. Signature verification failed.");
                    return Response.status(Response.Status.UNAUTHORIZED).build();
                }
                String deviceSignatureKey = device.getSigningKey();

                JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
                if (!JWSAlgorithm.ES256.equals(alg)) {
                    logger.error("Platform SSO: Unexpected JWS algorithm: " + alg + "(expected ES256)");
                    return Response.status(Response.Status.UNAUTHORIZED)
                            .type("application/platformsso-login-response+jwt")
                            .build();
                }
                PublicKey devicePublicKey = loadPlatformSSOPublicKey(deviceSignatureKey);
                ECDSAVerifier ecdsaVerifier = new ECDSAVerifier((ECPublicKey)
                        devicePublicKey);
                boolean ok = jwt.verify(ecdsaVerifier);
                logger.info("Platform SSO: Device public key verified: " + ok);
                if (!ok) {
                    logger.error("Platform SSO: Signature verification failed.");
                    return Response.status(Response.Status.UNAUTHORIZED)
                            .type("application/platformsso-login-response+jwt")
                            .build();
                }



            } catch (Exception e) {
                logger.error("Platform SSO: No device found. Aborting.: " + e.getMessage());
                logger.error("Platform SSO: Authentication attempt failed. ");

                return Response.status(Response.Status.UNAUTHORIZED)
                        .type("application/platformsso-login-response+jwt")
                        .build();
            }



        } catch (Exception e) {
            logger.error("Platform SSO: Error decrypting the JWT from the pre-authentication. "+e );
            logger.error(e);
            Response response = Response.status(Response.Status.BAD_REQUEST).build();
            return response;

        }

        return PSSOUtils.redirectIdp(session, state,nonce, scope,loginHint, clientId);

    }

    @GET
    @Path("/oidcflowcallback")
    @Produces(MediaType.APPLICATION_JSON)

    public Response getAccessCode(
            @QueryParam("code") String code,
            @QueryParam("state") String state,        // Optional, can be used to store RA info
            @Context jakarta.ws.rs.core.UriInfo uriInfo

    ) throws Exception {
        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("Platform SSO: Get authorization code request from: " + ip_address + ", User-Agent: " + userAgent);

        if (code == null || code.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing authorization code")
                    .build();
        }
        logger.info("Platform SSO: STATE: callback: " + state);
        logger.info("Platform SSO: Code: callback: " + code);
        String redirectTo = "com.apple.platformsso://callback?code=" + code+"&state="+state;
        return Response.status(302)
                    .location(URI.create(redirectTo))
                    .build();

    }


    @GET
    @Path("/authurl")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthURL(
            @HeaderParam("client-request-id") @DefaultValue("") String clientRequestId,
            @QueryParam("login_hint") @DefaultValue ("") String loginHint,
            @QueryParam("scope") @DefaultValue("openid profile") String scope


    ) throws Exception {

        logger.info("Platform SSO: Get pre-authentication request on the OIDC flow");
        KeycloakContext context = session.getContext();
        String ip_address = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        String userAgent = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        logger.info("Platform SSO: Get authorization URL request from: " + ip_address + ", User-Agent: " + userAgent);

        String state = UUID.randomUUID().toString();
        NonceService nonceService = new NonceService(session);
        String nonce = nonceService.createNonce(state);
        String baseURL = context.getUri().getBaseUri().toString();
        baseURL = baseURL.replaceAll("/$", "");
        String realm = session.getContext().getRealm().getName();

        logger.info("Platform SSO: Scopes: pre-auth: " + scope);
        String authUrl = baseURL + "/realms/"+realm+"/psso/authoidc?state="+state;

        // Create a Map instead of a manual JSON string
        Map<String, Object> response = new HashMap<>();
        Map<String, String> authorizationRequest = new HashMap<>();
        authorizationRequest.put("client_id", "psso-oidc");
        authorizationRequest.put("redirect_uri", "com.apple.platformsso://callback");
        authorizationRequest.put("response_type", "code");
        authorizationRequest.put("scope", scope);
        authorizationRequest.put("state", state);
        authorizationRequest.put("nonce", nonce);
        response.put("account_type", "Federated");
        response.put("federation_protocol", "OIDC");
        response.put("authorizationURL", authUrl);
        response.put("authorizationRequest",authorizationRequest);

        return Response.ok(response).build();


    }

}
