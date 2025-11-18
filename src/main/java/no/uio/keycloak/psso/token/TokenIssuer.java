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

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Token;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
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
    RefreshToken refreshToken = null;
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
                                          String nonce,
                                          boolean isRefresh
                                            ) {

        // 1) Create a transient authentication session (used by some flows)
        RootAuthenticationSessionModel root = session.authenticationSessions().createRootAuthenticationSession(realm);
        AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol("openid-connect");


        if (scope != null && !scope.isBlank()) {
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        }

        UserSessionModel userSession;
        AuthenticatedClientSessionModel clientSession;

        if (isRefresh && refreshToken.getType().equalsIgnoreCase("refresh")) {
            String sid = this.refreshToken.getSessionId();
            UserSessionModel existingUserSession = session.sessions().getUserSession(realm, sid);

            if (existingUserSession == null) {
                throw new RuntimeException("User session not found for sid=" + sid);
            }

            clientSession = existingUserSession.getAuthenticatedClientSessionByClient(client.getId());
            if (clientSession == null) {
                throw new RuntimeException("Client session not found in existing session.");
            }

            userSession = existingUserSession;

        }else {
            userSession = session.sessions().createUserSession(
                    null, /* id - let Keycloak generate */
                    realm,
                    user,
                    user.getUsername(),
                    session.getContext().getConnection().getRemoteAddr(),
                    "openid-connect",
                    true, /* rememberMe */
                    null,  /* brokerSessionId */
                    null,  /* brokerUserId */
                    UserSessionModel.SessionPersistenceState.PERSISTENT);
                    clientSession = session.sessions().createClientSession(realm, client, userSession);

        }

        // 3) Create an authenticated client session attached to the user session

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
        RefreshToken refreshTokenObject = builder.getRefreshToken();
        refreshTokenObject.setSubject(user.getUsername());
        refreshTokenObject.setPreferredUsername(user.getUsername());
        // Not necessary
        // Keycloak already sets sid for Refresh tokens
        // and don't do it when the refresh token is offline
       // refreshTokenObject.setSessionId(userSession.getId());
        //refreshTokenObject.setPreferredUsername(user.getUsername());
       // refreshTokenObject.setOtherClaims("tsid", clientSession.getId());

        String issuer = token.getIssuer();
        if (issuer == null) {
            logger.warn("Issuer had to be generated. Check if your hostname is right.");
            String baseUrl = session.getContext().getUri().getBaseUri().toString();
            String realmName = session.getContext().getRealm().getName();
            String newIssuer = baseUrl + "/realms/" + realmName;
            token.setOtherClaims("iss", newIssuer);
            if (refreshTokenObject.getIssuer() ==  null) {
                refreshTokenObject.setOtherClaims("iss", newIssuer);
            }
        }

        AccessTokenResponse response = builder.build();


        if (response == null) {
            logger.errorf("TokenManager response entity is null.");
            throw new IllegalStateException("TokenManager returned empty response entity");
        }

        long exp = calculateRefreshTokenExpiresIn(realm,client,userSession);
        response.setRefreshExpiresIn((int) exp);
        this.refreshExpiresIn = exp;
        this.expiresIn = realm.getAccessTokenLifespan();

        tm.transformAccessTokenResponse(session, response, userSession, clientCtx);

// 7) Pull signed token strings directly
        String accessToken = response.getToken();        // access_token (encoded JWT)
        String idToken = response.getIdToken();         // id_token (encoded JWT)
        String refreshTokenString = response.getRefreshToken(); // refresh_token (encoded JWT or opaque)
        return new IssuedTokens(accessToken, idToken, refreshTokenString);

    }

    private long calculateRefreshTokenExpiresIn(RealmModel realm,
                                                ClientModel client,
                                                UserSessionModel userSession) {

        final long now = Time.currentTime();

        // ---- Realm defaults ----
        long maxLifespan = Math.max(realm.getSsoSessionMaxLifespanRememberMe(), realm.getSsoSessionMaxLifespan());

        long idleTimeout = Math.max(realm.getSsoSessionIdleTimeout(), realm.getSsoSessionIdleTimeoutRememberMe());


        String clientMax = client.getAttribute("client.session.max.lifespan");
        if (clientMax != null && !clientMax.isEmpty()) {
            try {
                long v = Long.parseLong(clientMax);
                if (v > 0) maxLifespan = v;
            } catch (NumberFormatException ignored) {}
        }

        String clientIdle = client.getAttribute("client.session.idle.timeout");
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

    public void setRefreshToken(String refreshTokenString) {
        try {
            this.refreshToken = session.tokens().decode(refreshTokenString, RefreshToken.class);
        } catch (Exception e) {
            throw new RuntimeException("Invalid refresh token passed to TokenIssuer.setRefreshToken", e);
        }
    }



}
