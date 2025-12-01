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

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class AccessTokenValidator {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Logger logger = Logger.getLogger(AccessTokenValidator.class);

    public AccessTokenValidator(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    /**
     * Validates an AccessToken using Keycloak's internal signature verifier plus
     * additional security checks that decode() does NOT perform.
     *
     * @param tokenString the raw JWT
     * @param expectedClient the client id this token must be issued for (may be null if you don't want to enforce)
     * @return AccessToken if valid
     * @throws WebApplicationException if invalid
     */
    public AccessToken validate(String tokenString, String expectedClient) {
        AccessToken token;

        // 1. Signature + parsing
        try {
            token = verifyAndDecodeAccessToken(tokenString);
          //  token = session.tokens().decode(tokenString, AccessToken.class);
        } catch (Exception e) {
            throw unauthorized("Invalid token or signature");
        }

        if (token == null) {
            throw unauthorized("Malformed token");
        }

        // 2. Expiration
        if (token.getExp() != 0 &&
                token.getExp() < org.keycloak.common.util.Time.currentTime()) {
            throw unauthorized("Token expired");
        }

        // 3. Issuer check (required)
        String expectedIssuer = session.getContext().getUri().getBaseUriBuilder()
                .path("realms")
                .path(realm.getName())
                .build()
                .toString();

        if (!expectedIssuer.equals(token.getIssuer())) {
            throw unauthorized("Invalid issuer");
        }

        // 4. Audience / client binding
        if (expectedClient != null) {
            String[] audience = token.getAudience();

            boolean audienceOk = false;

            if (audience != null) {
                for (String aud : audience) {
                    if (expectedClient.equals(aud)) {
                        audienceOk = true;
                        break;
                    }
                }
            }

            // azp = "authorized party" (the client id)
            if (token.getIssuedFor() != null) {
                audienceOk = audienceOk || token.getIssuedFor().equals(expectedClient);
            }
            if (token.getOtherClaims().get("azp") != null) {
                audienceOk = audienceOk || token.getOtherClaims().get("azp").equals(expectedClient);
            }

            if (!audienceOk) {
                logger.error("Token not issued for the client: " + expectedClient);
                throw unauthorized("Token not issued for client " + expectedClient);
            }
        }

        // 5. Check if the session is still active
        String sessionState = token.getSessionId();
        if (sessionState == null) {
            logger.error("Session state not set");
            throw unauthorized("Token missing session state");
        }

        if (session.sessions().getUserSession(realm, sessionState) == null && session.sessions().getOfflineUserSession(realm, sessionState) == null) {
            logger.error("User session not found");
            throw unauthorized("User session expired or logged out");
        }

        // 6. Basic user check
        UserModel user = session.users().getUserById(realm, token.getSubject());
        if (user == null) {
            logger.error("User not found");
            throw unauthorized("User does not exist");
        }

        return token;
    }

    private WebApplicationException unauthorized(String msg) {
        return new WebApplicationException(
                Response.status(Response.Status.UNAUTHORIZED)
                        .entity(Map.of("error", msg))
                        .build());
    }

    private AccessToken verifyAndDecodeAccessToken(String tokenString) {
        final JWSInput jws;
        try {
            jws = new JWSInput(tokenString);
        } catch (JWSInputException e) {
            logger.error("JWSInput exception while parsing token", e);
            throw unauthorized("Invalid access token (malformed)");
        }

        // ===== Extract header =====
        String kid = jws.getHeader().getKeyId();
        String algRaw = jws.getHeader().getAlgorithm().name(); // e.g. "RS256", "HS512", ...

        logger.debugf("verifyAndDecodeAccessToken: alg=%s kid=%s", algRaw, kid);

        // Map JOSE alg → Keycloak alg
        String alg = switch (algRaw) {
            case "RS256" -> org.keycloak.crypto.Algorithm.RS256;
            case "RS384" -> org.keycloak.crypto.Algorithm.RS384;
            case "RS512" -> org.keycloak.crypto.Algorithm.RS512;
            case "ES256" -> org.keycloak.crypto.Algorithm.ES256;
            case "ES384" -> org.keycloak.crypto.Algorithm.ES384;
            case "ES512" -> org.keycloak.crypto.Algorithm.ES512;
            case "HS256" -> org.keycloak.crypto.Algorithm.HS256;
            case "HS384" -> org.keycloak.crypto.Algorithm.HS384;
            case "HS512" -> org.keycloak.crypto.Algorithm.HS512;
            default -> algRaw;
        };

        // ===== Determine realm from issuer (with failsafe) =====
        RealmModel tokenRealm = this.realm; // default
        String tokenIssuer = null;

        try {
            AccessToken partial = jws.readJsonContent(AccessToken.class);
            tokenIssuer = partial.getIssuer();

            if (tokenIssuer != null && !tokenIssuer.isBlank() && tokenIssuer.contains("/realms/")) {
                int idx = tokenIssuer.indexOf("/realms/");
                if (idx != -1) {
                    String realmName = tokenIssuer.substring(idx + "/realms/".length());
                    RealmModel byName = session.realms().getRealmByName(realmName);
                    if (byName != null) {
                        tokenRealm = byName;
                        logger.infof("Detected realm from issuer: %s", realmName);
                    } else {
                        logger.warnf("Issuer contains unknown realm '%s'. Falling back to context realm.", realmName);
                    }
                }
            } else if (tokenIssuer == null || tokenIssuer.isBlank()) {
                logger.info("Realm URL not set in access token, falling back to context realm");
            } else {
                logger.debugf("Issuer present but does not contain /realms/: %s", tokenIssuer);
            }
        } catch (Exception e) {
            logger.warn("Failed reading issuer from access token, using context realm", e);
        }

        // Build canonical expected issuer for the realm we resolved (so we can assert it)
        String expectedIssuerForTokenRealm = session.getContext().getUri().getBaseUriBuilder()
                .path("realms")
                .path(tokenRealm.getName())
                .build()
                .toString();

        logger.debugf("Using tokenRealm=%s expectedIssuer=%s", tokenRealm.getName(), expectedIssuerForTokenRealm);

        // ===== Fetch key from KeyManager =====
        KeyManager keyManager = session.keys();
        KeyWrapper keyWrapper = null;

        if (kid != null) {
            try {
                keyWrapper = keyManager.getKey(tokenRealm, kid, KeyUse.SIG, alg);
                if (keyWrapper != null) logger.debugf("Found key by kid: %s", kid);
            } catch (Exception ignored) {
                logger.debugf("KeyManager.getKey by kid failed for kid=%s alg=%s", kid, alg);
            }
        }

        if (keyWrapper == null) {
            try {
                keyWrapper = keyManager.getActiveKey(tokenRealm, KeyUse.SIG, alg);
                if (keyWrapper != null) logger.debug("Found active signing key for realm");
            } catch (Exception ignored) {
                logger.debugf("KeyManager.getActiveKey failed for realm=%s alg=%s", tokenRealm.getName(), alg);
            }
        }

        if (keyWrapper == null) {
            logger.errorf("Could not find key for verifying token (realm=%s, alg=%s, kid=%s)", tokenRealm.getName(), algRaw, kid);
            throw unauthorized("Unable to locate key for verifying access token (alg=" + algRaw + ")");
        }

        // =====================================================================
        //   CASE 1: HMAC (HS256/HS384/HS512)
        // =====================================================================
        if (algRaw.startsWith("HS")) {
            SecretKey secretKey = keyWrapper.getSecretKey();
            if (secretKey == null) {
                logger.errorf("HS-signed access token but no secret key available (realm=%s, alg=%s)", tokenRealm.getName(), algRaw);
                throw unauthorized("HS-signed access token but no secret key available");
            }

            String signingInput = jws.getEncodedHeader() + "." + jws.getEncodedContent();
            String macAlg = switch (algRaw) {
                case "HS256" -> "HmacSHA256";
                case "HS384" -> "HmacSHA384";
                case "HS512" -> "HmacSHA512";
                default -> throw unauthorized("Unsupported HMAC alg: " + algRaw);
            };

            try {
                Mac mac = Mac.getInstance(macAlg);
                mac.init(secretKey);
                byte[] computed = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));

                String expectedSig = base64UrlEncode(computed);
                String actualSig = base64UrlEncode(jws.getSignature());

                if (!expectedSig.equals(actualSig)) {
                    logger.warnf("HMAC signature mismatch (realm=%s, kid=%s, alg=%s)", tokenRealm.getName(), kid, algRaw);
                    throw unauthorized("Invalid access token (HMAC signature mismatch)");
                }

                // signature ok → ensure issuer matches expected issuer for this realm
                if (tokenIssuer == null || !tokenIssuer.equals(expectedIssuerForTokenRealm)) {
                    logger.warnf("Token issuer mismatch after HMAC verification: token.iss=%s expected=%s", tokenIssuer, expectedIssuerForTokenRealm);
                    throw unauthorized("Invalid access token (issuer mismatch)");
                }

                return jws.readJsonContent(AccessToken.class);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Exception e) {
                logger.error("Error during HMAC verification", e);
                throw unauthorized("Invalid access token (HMAC verification error)");
            }
        }

        // =====================================================================
        //   CASE 2: RSA / ECDSA
        // =====================================================================
        PublicKey publicKey = (PublicKey) keyWrapper.getPublicKey();
        if (publicKey == null) {
            logger.error("Asymmetric token but no public key available for verification");
            throw unauthorized("Asymmetric-signed access token but no public key available");
        }

        try {
            TokenVerifier<AccessToken> verifier =
                    TokenVerifier.create(tokenString, AccessToken.class)
                            .publicKey(publicKey);
                        //    .withDefaultChecks();  // exp, nbf, typ, iss

            verifier.verify();

            // TokenVerifier does basic iss check against the token content — but double-check it matches the realm we used
            AccessToken verified = verifier.getToken();
            String verifiedIss = verified.getIssuer();

            if (verifiedIss == null || !verifiedIss.equals(expectedIssuerForTokenRealm)) {
                logger.warnf("Token issuer did not point to the realm's expected issuer: token.iss=%s expected=%s", verifiedIss, expectedIssuerForTokenRealm);
                throw unauthorized("Invalid access token (issuer mismatch)");
            }

            return verified;

        } catch (VerificationException ve) {
            logger.info("Token verification failed: " + ve.getMessage());
            throw unauthorized("Invalid access token (signature/claims)");
        } catch (Exception e) {
            logger.error("Error verifying asymmetric token", e);
            throw unauthorized("Invalid access token (parsing)");
        }
    }

    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }


}
