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

package no.uio.keycloak.psso.badge;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * First-factor authenticator for printed QR badges.
 *
 * <p>On macOS Platform SSO web-based authentication the page's JavaScript calls
 * {@code window.apple.platformSSO.scanQR()}, which opens the camera in a secure system
 * process and resolves with the decoded payload; the payload is then posted here as an
 * ordinary form field. In a normal browser nothing happens and the pupil takes the
 * "sign in with a password instead" route.
 *
 * <p>Note the brute-force handling below. A custom authenticator gets <em>none</em> of
 * Keycloak's protection for free, and every way of getting it wrong fails open silently.
 *
 * <p>Deliberately <em>not</em> a {@code CredentialValidator}, even though it validates a
 * credential. When several ALTERNATIVE executions compete,
 * {@code DefaultAuthenticationFlow:436} does not run the one the admin put first - it runs
 * {@code createAuthenticationSelectionList(...).get(0)}. And with no user established yet,
 * {@code AuthenticationSelectionResolver} (:92-108) puts every userless
 * {@code CredentialValidator} *after* the ordinary authenticators, so the username/password
 * form would win the badge form every time regardless of flow order. Staying a plain
 * Authenticator keeps us in {@code nonCredentialExecutions}, which is in flow order.
 *
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class PSSOBadgeAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(PSSOBadgeAuthenticator.class);

    public static final String FORM = "psso-badge.ftl";
    public static final String FIELD_BADGE = "badge";
    public static final String FIELD_FALLBACK = "fallback";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(challenge(context, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        if (formData.containsKey(FIELD_FALLBACK)) {
            // The pupil asked for the password form. attempted() hands the flow to the next
            // ALTERNATIVE without recording anything against them.
            context.attempted();
            return;
        }

        PSSOBadgePayload payload = PSSOBadgePayload.parse(formData.getFirst(FIELD_BADGE));
        if (payload == null) {
            // Not one of our QR codes. There is no user to attribute this to, so there is
            // nothing to count: re-challenge rather than burn someone's lockout budget.
            logger.debug("Platform SSO: badge payload was absent or malformed");
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.forceChallenge(challenge(context, "pssoBadgeInvalid"));
            return;
        }

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserById(realm, payload.getUserId());

        if (user == null) {
            // Spend the work a real validation would, so the response time does not separate
            // "no such user id" from "wrong token".
            AuthenticatorUtils.dummyHash(context);
            logger.debugf("Platform SSO: badge references unknown user id %s", payload.getUserId());
            context.getEvent().error(Errors.USER_NOT_FOUND);
            context.forceChallenge(challenge(context, "pssoBadgeInvalid"));
            return;
        }

        // Obligation 1: AuthenticationManager.lookupUserForBruteForceLog resolves the user
        // from the authenticated user or from this note, and silently counts nothing if it
        // finds neither. Set it before any path that can fail.
        context.getAuthenticationSession()
                .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, user.getUsername());

        // Obligation 3: the lockout check is not automatic. Stock flows only get it because
        // AbstractUsernameFormAuthenticator.enabledUser() calls it on the way through - and
        // it calls it before the isEnabled() test, which is why the order here matches.
        //
        // forceChallenge, not failureChallenge, deliberately: this is what the stock
        // authenticator does, and it means a pupil who keeps waving an already-locked badge
        // at the camera does not keep extending their own lockout.
        String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
        if (bruteForceError != null) {
            context.getEvent().user(user).error(bruteForceError);
            context.forceChallenge(challenge(context, "pssoBadgeLocked"));
            return;
        }

        if (!user.isEnabled()) {
            // Also forceChallenge, as in stock: a disabled account is not a failed guess.
            context.getEvent().user(user).error(Errors.USER_DISABLED);
            context.forceChallenge(challenge(context, "pssoBadgeInvalid"));
            return;
        }

        CredentialModel matched = getCredentialProvider(context.getSession()).validateBadge(user, payload);
        if (matched == null) {
            logger.infof("Platform SSO: badge rejected for %s (sequence %d)",
                    user.getUsername(), payload.getSequence());
            context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
            // Obligation 2: only FAILED and FAILURE_CHALLENGE reach the brute-force counter.
            // forceChallenge() and attempted() would leave this unrecorded.
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    challenge(context, "pssoBadgeInvalid"));
            return;
        }

        logger.infof("Platform SSO: badge accepted for %s (sequence %d, credential %s)",
                user.getUsername(), payload.getSequence(), matched.getId());
        context.setUser(user);
        context.success();
    }

    private Response challenge(AuthenticationFlowContext context, String errorMessage) {
        var form = context.form();
        if (errorMessage != null) {
            form.setError(errorMessage);
        }
        return form.createForm(FORM);
    }

    /**
     * Must be false. The badge is what establishes identity, and
     * {@code DefaultAuthenticationFlow} throws UNKNOWN_USER outright for an authenticator
     * that claims to need a user before one is set.
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(realm, user, PSSOBadgeCredentialModel.TYPE);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Nothing to require: badges are issued out of band, not self-enrolled.
    }

    private PSSOBadgeCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (PSSOBadgeCredentialProvider) session.getProvider(
                CredentialProvider.class, PSSOBadgeCredentialProviderFactory.PROVIDER_ID);
    }

    @Override
    public void close() {
        // Not used
    }
}
