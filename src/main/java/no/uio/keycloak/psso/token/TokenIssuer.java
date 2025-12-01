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
import org.jboss.logging.Logger;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.common.util.Time;


import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
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
                                          boolean isRefresh,
                                          Device device
                                            ) {

        // 1) Create a transient authentication session (used by some flows)
        RootAuthenticationSessionModel root = session.authenticationSessions().createRootAuthenticationSession(realm);
        AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol("openid-connect");

        boolean rememberMe = realm.isRememberMe();
        if (scope != null && !scope.isBlank()) {
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        }
        String deviceUDID = device.getDeviceUDID();
        int nowSecs = Time.currentTime();
        UserSessionModel userSession = null;
        AuthenticatedClientSessionModel clientSession = null;

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
            Stream<UserSessionModel> existingUserSessions = session.sessions().getUserSessionsStream(realm, user);
            for (UserSessionModel existingSession : existingUserSessions.toList()){
                String sessionDeviceUDID = existingSession.getNotes().get("psso.udid");
                if (deviceUDID.equals(sessionDeviceUDID)){
                    userSession = existingSession;
                    clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
                    if (clientSession == null) {
                        clientSession = session.sessions().createClientSession(realm, client, userSession);

                    }
                }
            }
            if (userSession == null) {

                String uuid = UUID.randomUUID().toString();
                String ip = session.getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");

                UserSessionManager userSessionManager = new UserSessionManager(session);
                userSession = userSessionManager.createUserSession(uuid,  realm, user, user.getUsername(), ip, "psso", rememberMe, null, null, UserSessionModel.SessionPersistenceState.PERSISTENT);
/*
                userSession = session.sessions().createUserSession(
                        null,
                        realm,
                        user,
                        user.getUsername(),
                        session.getContext().getConnection().getRemoteAddr(),
                        "openid-connect",
                        true, //
                        null,  // brokerSessionId
                        null,  // brokerUserId
                        UserSessionModel.SessionPersistenceState.PERSISTENT);
                        */
              //  ClientSessionManager clientSessionManager = new ClientSessionManager(session);
                clientSession = session.sessions().createClientSession(realm, client, userSession);

            }

        }
        userSession.setNote("psso.udid",deviceUDID);
        userSession.setLastSessionRefresh(nowSecs);
        userSession.setState(UserSessionModel.State.LOGGED_IN);


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

        clientSession.setNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, "code");
        authSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, "code");

        // set scope notes so TokenManager sees them
        if (scope != null && !scope.isBlank()) {
            clientSession.setNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        }

        authSession.setAuthNote(AuthenticationManager.SSO_AUTH, "true");


        authSession.setProtocol("openid-connect");

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
        boolean isOffline = refreshTokenObject.getType().equals("Offline");
        long exp = calculateRefreshTokenExpiresIn(realm,client,userSession,isOffline);
        response.setRefreshExpiresIn((int) exp);
        this.refreshExpiresIn = exp;
        this.expiresIn = realm.getAccessTokenLifespan();
        TokenManager.attachAuthenticationSession(session, userSession,authSession);
        tm.transformAccessTokenResponse(session, response, userSession, clientCtx);


        int now = Time.currentTime(); // seconds in your KC version


// Manual checks exactly like KC (seconds arithmetic)
        boolean startedOk = (userSession.getStarted() + realm.getSsoSessionMaxLifespan()) > now;
        boolean refreshOk = (userSession.getLastSessionRefresh() + realm.getSsoSessionIdleTimeout()) > now;
        boolean stateOk = (userSession.getState() == UserSessionModel.State.LOGGED_IN);
        boolean realmMatch = userSession.getRealm() == realm || (userSession.getRealm() != null && userSession.getRealm().getId().equals(realm.getId()));




// 7) Pull signed token strings directly
        String accessToken = response.getToken();        // access_token (encoded JWT)
        String idToken = response.getIdToken();         // id_token (encoded JWT)
        String refreshTokenString = response.getRefreshToken(); // refresh_token (encoded JWT or opaque)
        return new IssuedTokens(accessToken, idToken, refreshTokenString);

    }

    private long calculateRefreshTokenExpiresIn(RealmModel realm,
                                                ClientModel client,
                                                UserSessionModel userSession, boolean isOffline) {

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


        if (isOffline){
            maxLifespan = realm.getOfflineSessionMaxLifespan();
            idleTimeout = realm.getOfflineSessionIdleTimeout();
            clientIdle = client.getAttribute("client.offline.session.idle.timeout");
            if  (clientIdle != null && !clientIdle.isEmpty()) {
                try {
                    long v = Long.parseLong(clientIdle);
                    if (v > 0) idleTimeout = v;
                } catch (NumberFormatException ignored) {
                }
            }
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
