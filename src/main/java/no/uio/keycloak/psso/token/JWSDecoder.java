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

package no.uio.keycloak.psso.token;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import jakarta.persistence.EntityManager;
import no.uio.keycloak.psso.Device;
import no.uio.keycloak.psso.UserPSSOCredentialData;
import no.uio.keycloak.psso.UserPSSOCredentialModel;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;


public class JWSDecoder {
    private  static Logger logger = Logger.getLogger(JWSDecoder.class);
    private final KeycloakSession session;
    String kid;
    public JWSDecoder(KeycloakSession session) {
        this.session = session;
    }

    public Map<String, Object> parseAndVerify(String jwsString) throws Exception {

        SignedJWT jwt = SignedJWT.parse(jwsString);

        JWSHeader header = jwt.getHeader();
        String kid = header.getKeyID();
        this.kid = kid;

        if (kid == null) {
            throw new IllegalArgumentException("Missing kid in JWS header.");
        }

        if (!"ES256".equals(header.getAlgorithm().getName())) {
            logger.error("Invalid JWS header algorithm: " + header.getAlgorithm().getName());
            throw new IllegalArgumentException("Unexpected alg for embedded assertion: " + header.getAlgorithm());
        }

        logger.infof("Platform SSO JWS kid: %s", kid);

        // --- 1) Load device by kid ---
        JpaConnectionProvider jpa = session.getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();

        Device device = em.createNamedQuery("Device.findBySignKeyId", Device.class)
                .setParameter("signingKeyId", kid)
                .getSingleResult();

        if (device == null) {
            logger.error("Device not found");
            throw new IllegalArgumentException("Unknown signing key ID for device: " + kid);
        }

        // --- 2) Convert stored public key (Base64 X9.63) -> ECPublicKey ---
        ECPublicKey publicKey = convertX963ToECPublicKey(device.getSigningKey());

        // --- 3) Verify ES256 signature ---
        JWSVerifier verifier = new ECDSAVerifier(publicKey);

        if (!jwt.verify(verifier)) {
            logger.error("JWS verification failed");
            throw new IllegalArgumentException("Invalid Platform SSO JWS signature.");
        }


        // --- 4) Return claims map ---
        return jwt.getJWTClaimsSet().getClaims();
    }

    /**
     * Convert Base64(X9.63) EC public key to Java ECPublicKey.
     * X9.63 = 0x04 || X || Y
     */
    public ECPublicKey convertX963ToECPublicKey(String base64) throws Exception {

        byte[] x963 = Base64.getDecoder().decode(base64);

        if (x963.length != 65 || x963[0] != 0x04) {
            throw new IllegalArgumentException("Invalid X9.63 public key format.");
        }

        byte[] xBytes = new byte[32];
        byte[] yBytes = new byte[32];

        System.arraycopy(x963, 1, xBytes, 0, 32);
        System.arraycopy(x963, 33, yBytes, 0, 32);

        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        ECPoint ecPoint = new ECPoint(x, y);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecSpec);

        return (ECPublicKey) keyFactory.generatePublic(keySpec);
    }



    public static void debugPrint(String jwsString) {
        try {
            // Parse the JWS (does NOT verify signature)
            SignedJWT jwt = SignedJWT.parse(jwsString);

            // Header
            JWSHeader header = jwt.getHeader();
            logger.info("----- JWS HEADER -----");
            logger.info(header.toJSONObject().toString());

            // Payload (claims)
            logger.info("----- JWS PAYLOAD -----");
            logger.info(jwt.getJWTClaimsSet().toJSONObject().toString());

        } catch (Exception e) {
            logger.info("Could not parse JWS: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public Map<String,Object> parseEmbeddedAssertion(String embeddedJwsString, UserModel user, String deviceUDID) throws Exception {
        SignedJWT jwt = SignedJWT.parse(embeddedJwsString);
        List<CredentialModel> credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(UserPSSOCredentialModel.TYPE)
                .toList();

        UserPSSOCredentialData credentialData = null;
        for (CredentialModel existingCred : credentials) {
            String id = existingCred.getId();
            UserPSSOCredentialData cd = UserPSSOCredentialModel.getCredentialData(existingCred);
            String currentDeviceUDID = cd.getDeviceUDID();
            if (deviceUDID.equals(currentDeviceUDID)) {
                credentialData = cd;
                break;
            }
        }


        String userKey = "";
        if (credentialData != null){
            userKey = credentialData.getUserSecureEnclaveKey();
        }else {
            throw new Exception("No credential data found for user "+user.getUsername());
        }


        // verify header

        ECPublicKey publicKey = convertX963ToECPublicKey(userKey);

        JWSVerifier verifier = new ECDSAVerifier(publicKey);
        if (!jwt.verify(verifier)) {
            throw new IllegalArgumentException("Invalid embedded assertion signature");
        }
        logger.info("JWS signature valid.");
        return jwt.getJWTClaimsSet().getClaims();
    }


    public String getKid(){
        return kid;
    }
}