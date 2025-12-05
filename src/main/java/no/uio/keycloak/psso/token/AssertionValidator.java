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

package no.uio.keycloak.psso.token;

import no.uio.keycloak.psso.Device;
import no.uio.keycloak.psso.NonceService;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

import java.net.URL;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class AssertionValidator {

    private static final Logger logger = Logger.getLogger(AssertionValidator.class);
    private final KeycloakSession session;

    public AssertionValidator(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Validates the decoded JWS claims from the Platform SSO login request.
     * Throws IllegalArgumentException on validation failure.
     */
    public Device validate(Map<String, Object> claims, Device device, String expectedAudience, String expectedIssuer, String clientRequestId) {

        // ---- iss ----
        String iss = (String) claims.get("iss");
        if (!Objects.equals(iss, expectedIssuer)) {
            logger.error("Invalid issuer");
            throw new IllegalArgumentException("Invalid issuer: " + iss);
        }

        // ---- sub / username ----
        String sub = (String) claims.get("sub");
        if (sub == null || sub.isEmpty()) {
            logger.error("Invalid sub");
            throw new IllegalArgumentException("Missing subject (sub).");
        }

        // ---- aud (audience) ----
        Object audObj = claims.get("aud");
        if (audObj instanceof String audStr) {
            if (!audStr.equals(expectedAudience)) {
                logger.error("Invalid audience: " + audStr);
                throw new IllegalArgumentException("Invalid audience: " + audStr);
            }
        } else if (audObj instanceof List<?> audList) {
            if (!audList.contains(expectedAudience)) {
                logger.error("Audience list does not contain expected value.");
                throw new IllegalArgumentException("Audience list does not contain expected value.");
            }
        } else {
            logger.error("Invalid audience Type");
            throw new IllegalArgumentException("Invalid audience type.");
        }

        // ---- iat / exp ----
        Instant now = Instant.now();
        Instant iat = getInstant(claims.get("iat"), "iat");
        Instant exp = getInstant(claims.get("exp"), "exp");

        if (iat.isAfter(now.plusSeconds(60))) {
            logger.error("Invalid iat.");
            throw new IllegalArgumentException("iat is in the future.");
        }

        if (exp.isBefore(now)) {
            logger.error("Token expired.");
            throw new IllegalArgumentException("Token has expired.");
        }

        // ---- scope ----
        String scope = (String) claims.get("scope");
        if (scope == null ||
                !scope.contains("openid") ||
                !scope.contains("urn:apple:platformsso")) {
            logger.error("Invalid scope: " + scope);
            throw new IllegalArgumentException("Invalid or missing scope.");
        }

        // ---- grant_type ----
        String grantType = (String) claims.get("grant_type");
        if (!"urn:ietf:params:oauth:grant-type:jwt-bearer".equals(grantType) || "refresh_token".equals(grantType)) {
            logger.error("Invalid grant type: " + grantType);
            throw new IllegalArgumentException("Invalid grant_type: " + grantType);
        }

        // ---- request_nonce ----
        String requestNonce = (String) claims.get("request_nonce");
        if (requestNonce == null || requestNonce.isEmpty()) {
            logger.error("Invalid request_nonce: " + requestNonce);
            throw new IllegalArgumentException("Missing request_nonce.");
        }

        NonceService nonceService = new NonceService(session);
        if (!nonceService.validateNonce(requestNonce, clientRequestId)){
            logger.error("Invalid nonce: " + requestNonce);
            throw new IllegalArgumentException("Invalid nonce: " + requestNonce);

        }

        // ---- signKeyId ----
        String signKeyId = (String) claims.get("signKeyId");
        if (!Objects.equals(signKeyId, device.getSigningKeyId())) {
            logger.error("Invalid signKeyId: " + signKeyId);
            throw new IllegalArgumentException("signKeyId mismatch.");
        }

        // ---- encKeyId ----
        String encKeyId = (String) claims.get("encKeyId");
        if (!Objects.equals(encKeyId, device.getEncryptionKeyId())) {
            logger.error("Invalid encKeyId: " + encKeyId);
            throw new IllegalArgumentException("encKeyId mismatch.");
        }

        // ---- jwe_crypto.apv ----
        Map<String, Object> jweCrypto = (Map<String, Object>) claims.get("jwe_crypto");
        if (jweCrypto == null || jweCrypto.get("apv") == null) {
            logger.error("Invalid jwe_crypto: " + jweCrypto);
            throw new IllegalArgumentException("Missing jwe_crypto.apv in request.");
        }

        logger.info("Assertion claims validated successfully for user "+sub);
        return device;
    }

    private Instant getInstant(Object value, String claimName) {
        if (value instanceof Date d) {
            return d.toInstant();
        }
        if (value instanceof Number n) {
            return Instant.ofEpochSecond(n.longValue());
        }
        throw new IllegalArgumentException("Invalid type for " + claimName + ": " + value.getClass());
    }

    public void validateEmbeddedAssertion(Map<String,Object> outer, Map<String,Object> inner, String username) {

        // Both assertions must have same request_nonce
        if (!Objects.equals(outer.get("request_nonce"), inner.get("request_nonce"))) {
            logger.error("Invalid request_nonce: " + inner.get("request_nonce"));
            throw new IllegalArgumentException("Embedded assertion request_nonce mismatch");
        }

        // Same nonce
        if (!Objects.equals(outer.get("nonce"), inner.get("nonce"))) {
            logger.error("Invalid nonce: " + inner.get("nonce"));
            throw new IllegalArgumentException("Embedded assertion nonce mismatch");
        }

        // Same sub
        if (!Objects.equals(outer.get("sub"), inner.get("sub"))) {
            logger.error("Invalid sub: " + inner.get("sub"));
            throw new IllegalArgumentException("Embedded assertion sub mismatch");
        }

        // Same scope
        if (!Objects.equals(outer.get("scope"), inner.get("scope"))) {
            logger.error("Invalid scope: " + inner.get("scope"));
            throw new IllegalArgumentException("Embedded assertion scope mismatch");
        }

        // Same iss
        if (!Objects.equals(username, inner.get("iss"))) {
            logger.error("Invalid issuer: " + inner.get("iss"));
            throw new IllegalArgumentException("Wrong issuer of the embedded assertion");
        }

        Object audObj = inner.get("aud");
        if (audObj instanceof String audStr) {
            if (!audStr.equals("psso")) {
                logger.error("Invalid audience: " + audStr);
                throw new IllegalArgumentException("Invalid audience: " + audStr);
            }
        } else if (audObj instanceof List<?> audList) {
            if (!audList.contains("psso")) {
                logger.error("Audience list does not contain expected value.");
                throw new IllegalArgumentException("Audience list does not contain expected value.");
            }
        } else {
            logger.error("Invalid audience Type");
            throw new IllegalArgumentException("Invalid audience type.");
        }

        // Check iat/exp fresh values
        Instant iat = getInstant(inner.get("iat"), "iat");
        Instant exp = getInstant(inner.get("exp"), "exp");

        Instant now = Instant.now();
        if (iat.isAfter(now.plusSeconds(60))) {
            logger.error("Embedded assertion iat is in the future: " + iat);
            throw new IllegalArgumentException("Embedded assertion iat is in the future");
        }
        if (exp.isBefore(now)) {
            logger.error("Embedded assertion expired");
            throw new IllegalArgumentException("Embedded assertion expired");
        }
    }

}
