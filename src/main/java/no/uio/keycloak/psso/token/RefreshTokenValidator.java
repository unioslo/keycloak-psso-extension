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

import com.nimbusds.jose.crypto.impl.ECDSAProvider;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.models.*;
import org.keycloak.representations.RefreshToken;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class RefreshTokenValidator {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Logger logger =  Logger.getLogger(RefreshTokenValidator.class);

    public RefreshTokenValidator(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    /**
     * Validates a Keycloak refresh token (custom or default) without requiring HTTP context.
     *
     * @param refreshTokenString raw refresh token JWT
     * @param expectedClientId   the clientId the token must belong to ("psso")
     */
    public RefreshToken validate(String refreshTokenString, String expectedClientId) {
        RefreshToken token;

        //
        // 1. Signature + parsing
        //
        try {
            token = verifyAndDecode(refreshTokenString);
            //token = session.tokens().decode(refreshTokenString, RefreshToken.class);
        } catch (Exception e) {
            throw unauthorized("Invalid refresh token (signature/format)");
        }

        if (token == null) {
            throw unauthorized("Malformed refresh token");
        }

        //
        // 2. Check token type: Refresh or Offline
        //
        String typ = token.getType();
        boolean isOffline = "Offline".equals(typ);
        boolean isRefresh = "Refresh".equals(typ);

        if (!isRefresh && !isOffline) {
            throw unauthorized("Invalid token type: " + typ);
        }

        //
        // 3. Expiration (Keycloak does NOT check this automatically)
        //

        if (isRefresh || (isOffline && token.getExp() != null)) {
            if (token.getExp() > 0 &&
                    token.getExp() < Time.currentTime()) {
                throw unauthorized("Refresh token expired");
            }
        }

        //
        // 4. Issuer check
        //
        String expectedIssuer = session.getContext().getUri().getBaseUriBuilder()
                .path("realms")
                .path(realm.getName())
                .build()
                .toString();

        if (!expectedIssuer.equals(token.getIssuer())) {
            throw unauthorized("Invalid issuer");
        }

        //
        // 5. Audience / client binding
        //
        boolean audienceOk = false;


        // issuedFor
        if (token.getIssuedFor() != null) {
            audienceOk = audienceOk || token.getIssuedFor().equals(expectedClientId);
        }

        // azp = authorized party
        if (token.getOtherClaims().get("azp") != null) {
            audienceOk = audienceOk || token.getOtherClaims().get("azp").equals(expectedClientId);
        }

        if (!audienceOk) {
            throw unauthorized("Refresh token not issued for client " + expectedClientId);
        }

        //
        // Offline tokens STOP here — no session binding required
        //
        if (isOffline) {
            return token;
        }

        //
        // 6. Refresh tokens (session-bound): user session must exist
        //
        
        String sid = token.getSessionId();
        if (sid == null) {
            throw unauthorized("Refresh token missing session_state");
        }

        UserSessionModel userSession =
                session.sessions().getUserSession(realm, sid);

        if (userSession == null) {
            throw unauthorized("User session ended or logged out");
        }

        //
        // 7. User must still exist
        //
        UserModel user = session.users().getUserByUsername(realm, token.getSubject());
        if (user == null) {
            throw unauthorized("User no longer exists");
        }

        //
        // 8. Idle timeout check (same as Keycloak)
        //
        int now = Time.currentTime();
        if (now - userSession.getLastSessionRefresh() >
                realm.getSsoSessionIdleTimeout()) {
            throw unauthorized("Session idle timeout exceeded");
        }

        //
        // Valid, session-bound refresh token
        //
        return token;
    }


    private WebApplicationException unauthorized(String msg) {
        logger.error(msg);
        return new WebApplicationException(

                Response.status(Response.Status.UNAUTHORIZED)
                        .entity(Map.of("error", msg))
                        .build());
    }

    private RefreshToken verifyAndDecode(String refreshTokenString) {
        final JWSInput jws;
        try {
            jws = new JWSInput(refreshTokenString);
        } catch (JWSInputException e) {
            throw unauthorized("Invalid refresh token (malformed)");
        }

        // === Extract header info ===
        String kid = jws.getHeader().getKeyId();
        String algRaw = jws.getHeader().getAlgorithm().name();   // e.g., "HS512", "RS256", ...

        // === Normalize algorithm so Keycloak KeyManager understands it ===
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

        // === Determine correct realm from issuer ===
        RealmModel tokenRealm = this.realm;
        try {
            RefreshToken partial = jws.readJsonContent(RefreshToken.class);
            String iss = partial.getIssuer();
            int last = iss.lastIndexOf('/');
            if (last != -1 && last + 1 < iss.length()) {
                String realmName = iss.substring(last + 1);
                RealmModel fromIssuer = session.realms().getRealmByName(realmName);
                if (fromIssuer != null) tokenRealm = fromIssuer;
            }
        } catch (Exception ignored) {}

        // === Load key from KeyManager ===
        KeyManager keyManager = session.keys();
        KeyWrapper keyWrapper = null;

        if (kid != null) {
            try {
                keyWrapper = keyManager.getKey(tokenRealm, kid, KeyUse.SIG, alg);
            } catch (Exception ignored) {}
        }

        if (keyWrapper == null) {
            try {
                keyWrapper = keyManager.getActiveKey(tokenRealm, KeyUse.SIG, alg);
            } catch (Exception ignored) {}
        }

        if (keyWrapper == null) {
            throw unauthorized("Unable to locate key for verifying token (alg=" + algRaw + ")");
        }

        // --------------------------------------------------------------------
        //                 CASE 1: HMAC-SIGNED TOKEN (HS256/384/512)
        // --------------------------------------------------------------------
        if (algRaw.startsWith("HS")) {
            SecretKey secretKey = keyWrapper.getSecretKey();
            if (secretKey == null) {
                throw unauthorized("HS-signed refresh token but no secret key available");
            }

            String jwsSigningInput = jws.getEncodedHeader() + "." + jws.getEncodedContent();
            String macAlg = switch (algRaw) {
                case "HS256" -> "HmacSHA256";
                case "HS384" -> "HmacSHA384";
                case "HS512" -> "HmacSHA512";
                default -> throw unauthorized("Unsupported HMAC alg: " + algRaw);
            };

            try {
                Mac mac = Mac.getInstance(macAlg);
                mac.init(secretKey);
                byte[] computedSig = mac.doFinal(jwsSigningInput.getBytes(StandardCharsets.US_ASCII));

                String expectedSig = base64UrlEncode(computedSig);
                String actualSig = base64UrlEncode(jws.getSignature());

                if (!expectedSig.equals(actualSig)) {
                    throw unauthorized("Invalid refresh token (HMAC signature mismatch)");
                }

                // Signature OK → decode JSON
                return jws.readJsonContent(RefreshToken.class);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Exception e) {
                throw unauthorized("Invalid refresh token (HMAC verification error)");
            }
        }

        // --------------------------------------------------------------------
        //              CASE 2: ASYMMETRIC-SIGNED TOKEN (RS / ES)
        // --------------------------------------------------------------------
        PublicKey publicKey = (PublicKey) keyWrapper.getPublicKey();
        if (publicKey == null) {
            throw unauthorized("Asymmetric token but no public key available");
        }

        try {
            TokenVerifier<RefreshToken> verifier =
                    TokenVerifier.create(refreshTokenString, RefreshToken.class)
                            .publicKey(publicKey)
                            .withDefaultChecks(); // exp, nbf, iss

            verifier.verify();
            return verifier.getToken();

        } catch (VerificationException ve) {
            throw unauthorized("Invalid refresh token (signature/claims)");
        } catch (Exception e) {
            throw unauthorized("Invalid refresh token (parsing)");
        }
    }

    private static String base64UrlEncode(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
