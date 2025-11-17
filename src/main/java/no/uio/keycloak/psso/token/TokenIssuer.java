package no.uio.keycloak.psso.token;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Token;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.common.util.Time;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class TokenIssuer {
    private static final Logger logger = Logger.getLogger(TokenIssuer.class);
    private final KeycloakSession session;
    public  long expiresIn = 0;
    public long refreshExpiresIn = 0;
    public TokenIssuer(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Issue signed tokens (raw JWT strings) for a validated user.
     *
     * @param realm    RealmModel
     * @param user     UserModel (already validated)
     * @param client   ClientModel (psso client)
     * @param scope    scope string (e.g. "openid offline_access urn:apple:platformsso")
     * @param event    EventBuilder (should be pre-filled with event/client/user)
     * @return IssuedTokens containing signed token strings (access, id, refresh)
     */
    public IssuedTokens issueSignedTokens(RealmModel realm,
                                          UserModel user,
                                          ClientModel client,
                                          String scope,
                                          EventBuilder event,
                                          String nonce) {

        // 1) Create a transient authentication session (used by some flows)
        RootAuthenticationSessionModel root = session.authenticationSessions().createRootAuthenticationSession(realm);
        AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol("openid-connect");
        if (scope != null && !scope.isBlank()) {
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        }

        // 2) Create a persistent user session using the non-deprecated signature.
        UserSessionModel userSession = session.sessions().createUserSession(
                null, /* id - let Keycloak generate */
                realm,
                user,
                user.getUsername(),
                session.getContext().getConnection().getRemoteAddr(),
                "openid-connect",
                true, /* rememberMe */
                null,  /* brokerSessionId */
                null,  /* brokerUserId */
                UserSessionModel.SessionPersistenceState.PERSISTENT
        );

        // 3) Create an authenticated client session attached to the user session
        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);

        // --- Begin: ensure minimum required clientSession/authSession state ----------------

        // protocol
        clientSession.setProtocol("openid-connect");


        // ensure redirectUri present on clientSession (use client's rootUrl or first redirect uri)
        String redirect = client.getRootUrl();
        if (redirect == null || redirect.isBlank()) {
            if (!client.getRedirectUris().isEmpty()) {
                redirect = client.getRedirectUris().iterator().next();
            }
        }
        if (redirect != null && !redirect.isBlank()) {
            clientSession.setRedirectUri(redirect);
            clientSession.setNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirect);
            authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirect);
        }

        // set response_type - choose "code" as standard; use "id_token token" only if you need implicit behavior
        // Using "code" signals the builder that an authorization flow was intended/completed.
        clientSession.setNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, "code");
        authSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, "code");

        // set scope notes so TokenManager sees them
        if (scope != null && !scope.isBlank()) {
            clientSession.setNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        }

        // timestamps - some TokenManager logic reads timestamps on clientSession/userSession
        int nowSecs = (int) (Time.currentTime() / 1000L);
       // clientSession.setTimestamp(nowSecs);
        userSession.setLastSessionRefresh(nowSecs);

        // make sure root/auth sessions know protocol
        //root.setProtocol("openid-connect");
        authSession.setProtocol("openid-connect");

        // --- End: clientSession/authSession fixes ----------------------------------------

        // 4) Build ClientSessionContext from client session and client's client-scope set

        Set<ClientScopeModel> scopes = TokenManager.getRequestedClientScopes(
                session,
                scope,
                client,
                user
        ).collect(Collectors.toSet());

        DefaultClientSessionContext clientCtx = DefaultClientSessionContext.fromClientSessionAndClientScopes(
                clientSession,
                scopes,
                session
        );


        // Debug: log clientCtx scopes and notes
        try {
           // logger.debugf("clientCtx scopes: %s", clientCtx.getClientScopes().stream().map(ClientScopeModel::getName).collect(Collectors.joining(",")));
            logger.debugf("clientSession notes: %s", clientSession.getNotes());
        } catch (Exception e) {
            // ignore logging errors
        }

        // 5) Use TokenManager.responseBuilder(...) (the real token factory on KC 26.x)
        TokenManager tm = new TokenManager();
        TokenManager.AccessTokenResponseBuilder builder =
                tm.responseBuilder(realm, client, event, session, userSession, clientCtx);


// Optional: explicitly generate the tokens you want (not strictly required
// because build() will generate as needed, but explicit is clear)
        builder.generateAccessToken()
                .generateIDToken()
                .generateRefreshToken();

        IDToken token = builder.getIdToken();
        //token.setOtherClaims("nonce", nonce);
        token.setNonce(nonce);
        token.setSessionId(userSession.getId());
        String issuer = token.getIssuer();
        if (issuer == null) {
            logger.warn("Issuer had to be generated. Check if your hostname is right.");
            String baseUrl = session.getContext().getUri().getBaseUri().toString();
            String realmName = session.getContext().getRealm().getName();
            String newIssuer = baseUrl + "/realms/" + realmName;
            token.setOtherClaims("iss", newIssuer);
        }





// If you want an offline token (refresh token that persists), enable it when building:
// builder.offlineToken(true);

// 6) Build the AccessTokenResponse (this produces an AccessTokenResponse object
// which may contain *token objects* but the encoded strings can be null at this point)
        AccessTokenResponse response = builder.build();


        if (response == null) {
            logger.errorf("TokenManager response entity is null.");
            throw new IllegalStateException("TokenManager returned empty response entity");
        }

        long exp = calculateRefreshTokenExpiresIn(realm,client,userSession);
        response.setRefreshExpiresIn((int) exp);
        this.refreshExpiresIn = exp;
        this.expiresIn = realm.getAccessTokenLifespan();

// 6b) **Important:** transform/encode the AccessTokenResponse into actual token strings
// and attach it to the user/session context. This populates the encoded token strings
// (access_token, id_token, refresh_token) inside the response object.
        tm.transformAccessTokenResponse(session, response, userSession, clientCtx);

// 7) Pull signed token strings directly
        String accessToken = response.getToken();        // access_token (encoded JWT)
        String idToken = response.getIdToken();         // id_token (encoded JWT)
        String refreshToken = response.getRefreshToken(); // refresh_token (encoded JWT or opaque)


// Logging so you can see concrete output
        logger.infof("Response object: %s", response);
        logger.infof("Token type: %s", response.getTokenType());
        logger.infof("Issued tokens for user %s (access %b id %b refresh %b)",
                user.getUsername(),
                accessToken != null,
                idToken != null,
                refreshToken != null);
        logger.info("ID: " + idToken);
        logger.info("Refresh token: " + refreshToken);
        return new IssuedTokens(accessToken, idToken, refreshToken);

    }

    private long calculateRefreshTokenExpiresIn(RealmModel realm,
                                                ClientModel client,
                                                UserSessionModel userSession) {

        final long now = Time.currentTime();
        logger.info("now=" + now);
        logger.info("started=" + userSession.getStarted());
        logger.info("lastRefresh=" + userSession.getLastSessionRefresh());
        logger.info("realmMax=" + realm.getSsoSessionMaxLifespan());
        logger.info("realmIdle=" + realm.getSsoSessionIdleTimeout());
        logger.info("realmMaxRM=" + realm.getSsoSessionMaxLifespanRememberMe());
        logger.info("realmIdleRM=" + realm.getSsoSessionIdleTimeoutRememberMe());
        logger.info("clientMax=" + client.getAttribute("sso.session.max.lifespan"));
        logger.info("clientIdle=" + client.getAttribute("sso.session.idle.timeout"));

        // ---- Realm defaults ----
        long maxLifespan = Math.max(realm.getSsoSessionMaxLifespanRememberMe(), realm.getSsoSessionMaxLifespan());

        long idleTimeout = Math.max(realm.getSsoSessionIdleTimeout(), realm.getSsoSessionIdleTimeoutRememberMe());

        // ---- Client overrides ----
        String clientMax = client.getAttribute("sso.session.max.lifespan");
        if (clientMax != null && !clientMax.isEmpty()) {
            try {
                long v = Long.parseLong(clientMax);
                if (v > 0) maxLifespan = v;
            } catch (NumberFormatException ignored) {}
        }

        String clientIdle = client.getAttribute("sso.session.idle.timeout");
        if (clientIdle != null && !clientIdle.isEmpty()) {
            try {
                long v = Long.parseLong(clientIdle);
                if (v > 0) idleTimeout = v;
            } catch (NumberFormatException ignored) {}
        }

        // ---- Expiration timestamps ----

        long finalExp = Math.min(maxLifespan, idleTimeout);

       // long refreshExpiresIn =  now + finalExp;

        return finalExp;
    }

}
