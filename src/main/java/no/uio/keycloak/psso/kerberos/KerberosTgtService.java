package no.uio.keycloak.psso.kerberos;

import no.uio.keycloak.psso.Device;
import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Attaches a Kerberos TGT to the Platform SSO login response.
 *
 * Nothing is persisted: a ticket is obtained per login response and travels inside the
 * device-bound JWE.
 */
public final class KerberosTgtService {

    private static final Logger logger = Logger.getLogger(KerberosTgtService.class);

    private final KerberosRealmConfig config;

    private KerberosTgtService(KerberosRealmConfig config) {
        this.config = config;
    }

    /**
     * Adds a TGT to the login response if the realm is configured for one.
     *
     * The only way this interferes with issuing SSO tokens is when the realm explicitly opts into
     * {@code kerberosFailureMode=fail}, in which case it throws {@link KerberosTgtException}.
     * Everything else — Kerberos switched off, unreadable configuration, an unreachable KDC, a
     * rejected credential — is logged and ignored, leaving {@code body} untouched.
     */
    public static void attachIfConfigured(RealmModel realm, JSONObject body, UserModel user,
                                          Device device, Map<String, Object> claims) {
        KerberosRealmConfig config;
        try {
            config = KerberosRealmConfig.forRealm(realm).orElse(null);
        } catch (RuntimeException e) {
            // Reading configuration must never break sign-in. Note we cannot honour failHard
            // here: whether it is set is precisely what we failed to read.
            logger.error("Platform SSO: Could not read Kerberos configuration; "
                    + "returning login response without a ticket.", e);
            return;
        }
        if (config == null) {
            // DEBUG, not INFO: realms that never use Kerberos would otherwise log on every login.
            logger.debug("Platform SSO: Kerberos is disabled or unconfigured for this realm; no TGT.");
            return;
        }
        new KerberosTgtService(config).attachTgt(body, user, device, claims);
    }

    void attachTgt(JSONObject body, UserModel user, Device device, Map<String, Object> claims) {
        // Declared outside the try so failures can name the principal actually attempted, which
        // is usually the thing that is wrong.
        String principal = null;
        try {
            if (!requested(claims)) {
                logger.debugf("Platform SSO: Device %s did not request a Kerberos ticket ('%s' absent "
                        + "from the assertion); no TGT.", device.getSerialNumber(), config.triggerClaim());
                return;
            }

            principal = resolvePrincipal(user);
            if (principal == null) {
                logger.warnf("Platform SSO: Cannot resolve a Kerberos principal for user %s; skipping TGT.",
                        user.getUsername());
                return;
            }

            KerberosTgtProvider provider = selectProvider(device, claims);
            if (provider == null) {
                return;
            }

            KerberosTgt tgt = provider.obtain(new KerberosTgtRequest(principal, password(claims), user));
            body.put(config.ticketKeyPath(), tgt.toAppleDictionary());

            logger.infof("Platform SSO: User %s on device %s received a Kerberos TGT for %s via %s.",
                    user.getUsername(), device.getSerialNumber(), tgt.realm(), provider.name());

        } catch (Exception e) {
            if (config.failHard()) {
                throw new KerberosTgtException("Kerberos TGT acquisition failed for user "
                        + user.getUsername() + ": " + e.getMessage(), e);
            }
            // A rejected credential or unknown principal is routine, so keep the stack trace for
            // DEBUG rather than dumping it on every mistyped password.
            logger.errorf("Platform SSO: Kerberos TGT acquisition failed for principal %s (%s); "
                    + "returning login response without a ticket.", principal, e.getMessage());
            logger.debug("Platform SSO: Kerberos failure detail", e);
        }
    }

    /**
     * Chosen from the credential this request actually carries, not from how the device enrolled.
     * A device's registration method describes its enrollment, not this authentication, so it
     * would be the wrong thing to gate on; it is logged only as context.
     */
    private KerberosTgtProvider selectProvider(Device device, Map<String, Object> claims) throws Exception {
        if (password(claims) != null) {
            return new PasswordTgtProvider(config);
        }
        // Secure Enclave, refresh and token-exchange grants carry no password; the Keycloak
        // session is the proof of identity and PKINIT turns it into something a KDC accepts.
        if (config.pkinitConfigured()) {
            return new PkinitTgtProvider(config, new LocalCaIssuer(
                    config.localCaCertPem(), config.localCaKeyPem(), config.certLifetimeSeconds()));
        }
        logger.debugf("Platform SSO: No password in this request (device %s registered via %s) and "
                + "PKINIT is not configured (CA cert, CA key and KDC anchors required); no TGT issued.",
                device.getSerialNumber(), device.getRegistrationMethod());
        return null;
    }

    /**
     * Whether this Mac asked for a ticket.
     *
     * The SSO extension can signal intent either as a custom body claim
     * ({@code setCustomLoginRequestBodyClaims}) or as an extra scope ({@code additionalScopes}),
     * so both are accepted under the same configured name and the Swift side can use whichever
     * fits. Lets an MDM admin enable Kerberos only for machines that can actually reach the KDC,
     * which also avoids every off-domain login paying the KDC connect timeout.
     *
     * This is a deployment control, not a security boundary: the assertion is signed by the
     * device key, so an unregistered device cannot forge it, but a registered one could always
     * ask. Restricting who may obtain tickets belongs on the Keycloak side.
     */
    private boolean requested(Map<String, Object> claims) {
        String trigger = config.triggerClaim();
        if (trigger.isEmpty()) {
            return true;
        }
        if (claims == null) {
            return false;
        }
        if (isTruthy(claims.get(trigger))) {
            return true;
        }
        if (claims.get("scope") instanceof String scope) {
            for (String token : scope.split("\\s+")) {
                if (token.equals(trigger)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isTruthy(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof Boolean flag) {
            return flag;
        }
        String text = String.valueOf(value).trim();
        return !text.isEmpty() && !text.equalsIgnoreCase("false") && !text.equals("0");
    }

    private String resolvePrincipal(UserModel user) {
        String base = config.principalAttribute().isEmpty()
                ? user.getUsername()
                : user.getFirstAttribute(config.principalAttribute());

        if (base == null || base.isBlank()) {
            return null;
        }
        base = base.trim();
        return base.contains("@") ? base : base + "@" + config.realm();
    }

    private static String password(Map<String, Object> claims) {
        Object password = claims == null ? null : claims.get("password");
        if (password instanceof String value && !value.isEmpty()) {
            return value;
        }
        return null;
    }
}
