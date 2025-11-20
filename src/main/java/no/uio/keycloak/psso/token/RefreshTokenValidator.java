package no.uio.keycloak.psso.token;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.representations.RefreshToken;

import java.util.Map;

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
            token = session.tokens().decode(refreshTokenString, RefreshToken.class);
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
        if (token.getExp() > 0 &&
                token.getExp() < Time.currentTime()) {
            throw unauthorized("Refresh token expired");
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
        String sid = token.getSessionState();
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
}
