package no.uio.keycloak.psso.kerberos;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ui.extend.UiTabProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Typed view of the Kerberos settings on the realm's "Platform Single Sign-on" tab.
 *
 * Returns empty whenever Kerberos is switched off or misconfigured, so callers can treat "no
 * config" and "not enabled" identically and simply skip ticket issuance.
 */
public final class KerberosRealmConfig {

    private static final Logger logger = Logger.getLogger(KerberosRealmConfig.class);

    private static final String PSSO_TAB = "Platform Single Sign-on";
    private static final String DEFAULT_TICKET_KEY_PATH = "login_tgt";
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_KDC_PORT = 88;

    public record KdcAddress(String host, int port) { }

    private final String realm;
    private final List<KdcAddress> kdcs;
    private final String ticketKeyPath;
    private final String principalAttribute;
    private final AsRepKeyMode asRepKeyMode;
    private final boolean failHard;
    private final int timeoutMs;

    private KerberosRealmConfig(String realm, List<KdcAddress> kdcs, String ticketKeyPath,
                                String principalAttribute,
                                AsRepKeyMode asRepKeyMode, boolean failHard, int timeoutMs) {
        this.realm = realm;
        this.kdcs = kdcs;
        this.ticketKeyPath = ticketKeyPath;
        this.principalAttribute = principalAttribute;
        this.asRepKeyMode = asRepKeyMode;
        this.failHard = failHard;
        this.timeoutMs = timeoutMs;
    }

    public String realm() {
        return realm;
    }

    public List<KdcAddress> kdcs() {
        return kdcs;
    }

    public String ticketKeyPath() {
        return ticketKeyPath;
    }

    public String principalAttribute() {
        return principalAttribute;
    }

    public AsRepKeyMode asRepKeyMode() {
        return asRepKeyMode;
    }

    public boolean failHard() {
        return failHard;
    }

    public int timeoutMs() {
        return timeoutMs;
    }


    public static Optional<KerberosRealmConfig> forRealm(RealmModel realm) {
        ComponentModel model = realm.getComponentsStream(realm.getId(), UiTabProvider.class.getName())
                .filter(c -> PSSO_TAB.equals(c.getProviderId()))
                .findFirst()
                .orElse(null);
        if (model == null) {
            return Optional.empty();
        }
        if (!Boolean.parseBoolean(model.get("kerberosEnabled"))) {
            return Optional.empty();
        }

        String kerberosRealm = trimToNull(model.get("kerberosRealm"));
        if (kerberosRealm == null) {
            logger.warn("Platform SSO: Kerberos is enabled but no realm is configured; skipping TGT issuance.");
            return Optional.empty();
        }
        kerberosRealm = kerberosRealm.toUpperCase();

        List<KdcAddress> kdcs = parseKdcHosts(model.get("kerberosKdcHosts"));
        if (kdcs.isEmpty()) {
            logger.warn("Platform SSO: Kerberos is enabled but no KDC hosts are configured; skipping TGT issuance.");
            return Optional.empty();
        }

        String ticketKeyPath = Optional.ofNullable(trimToNull(model.get("kerberosTicketKeyPath")))
                .orElse(DEFAULT_TICKET_KEY_PATH);
        String principalAttribute = Optional.ofNullable(trimToNull(model.get("kerberosPrincipalAttribute")))
                .orElse("");
        boolean failHard = "fail".equalsIgnoreCase(trimToNull(model.get("kerberosFailureMode")));
        int timeoutMs = parsePositiveInt(model.get("kerberosTimeoutMs"), DEFAULT_TIMEOUT_MS);

        return Optional.of(new KerberosRealmConfig(
                kerberosRealm,
                kdcs,
                ticketKeyPath,
                principalAttribute,
                AsRepKeyMode.fromConfig(model.get("kerberosAsRepKeyMode")),
                failHard,
                timeoutMs));
    }

    /**
     * Parses "host", "host:port" and bracketed IPv6 forms "[::1]" / "[::1]:88". A bare IPv6
     * literal is left intact: its colons are part of the address, not a port separator.
     */
    static List<KdcAddress> parseKdcHosts(String raw) {
        List<KdcAddress> addresses = new ArrayList<>();
        if (raw == null) {
            return addresses;
        }
        for (String entry : raw.split(",")) {
            String token = entry.trim();
            if (token.isEmpty()) {
                continue;
            }

            String host = token;
            String portPart = null;

            if (token.startsWith("[")) {
                int close = token.indexOf(']');
                if (close < 0) {
                    logger.warnf("Platform SSO: Ignoring malformed KDC address '%s'.", token);
                    continue;
                }
                host = token.substring(1, close);
                String rest = token.substring(close + 1).trim();
                if (rest.startsWith(":")) {
                    portPart = rest.substring(1);
                }
            } else if (token.indexOf(':') == token.lastIndexOf(':') && token.indexOf(':') > 0) {
                // Exactly one colon, so this is host:port rather than an IPv6 literal.
                int colon = token.indexOf(':');
                host = token.substring(0, colon);
                portPart = token.substring(colon + 1);
            }

            int port = DEFAULT_KDC_PORT;
            if (portPart != null) {
                int parsed = parsePositiveInt(portPart, -1);
                if (parsed > 0 && parsed <= 65535) {
                    port = parsed;
                } else {
                    logger.warnf("Platform SSO: Ignoring unparseable KDC port in '%s'; defaulting to %d.",
                            token, DEFAULT_KDC_PORT);
                }
            }

            host = host.trim();
            if (!host.isEmpty()) {
                addresses.add(new KdcAddress(host, port));
            }
        }
        return addresses;
    }


    private static int parsePositiveInt(String raw, int fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            int value = Integer.parseInt(raw.trim());
            return value > 0 ? value : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
