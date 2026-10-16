/* Copyright 2026 University of Oslo, Norway
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
    private static final int DEFAULT_CERT_LIFETIME_SECONDS = 60;

    public record KdcAddress(String host, int port) { }

    private final String realm;
    private final List<KdcAddress> kdcs;
    private final String ticketKeyPath;
    private final String principalAttribute;
    private final String triggerClaim;
    private final AsRepKeyMode asRepKeyMode;
    private final boolean failHard;
    private final int timeoutMs;
    private final String kdcAnchorsPem;
    private final String kdcCertName;
    private final int certLifetimeSeconds;
    private final CertSource certSource;
    // LOCAL_CA path (FreeIPA):
    private final String localCaCertPem;
    private final String localCaKeyPem;
    // AGENT_SERVICE path (Active Directory):
    private final String agentServiceUrl;
    private final String agentClientCertPem;
    private final String agentClientKeyPem;
    private final String agentServerCaPem;

    private KerberosRealmConfig(Builder b) {
        this.realm = b.realm;
        this.kdcs = b.kdcs;
        this.ticketKeyPath = b.ticketKeyPath;
        this.principalAttribute = b.principalAttribute;
        this.triggerClaim = b.triggerClaim;
        this.asRepKeyMode = b.asRepKeyMode;
        this.failHard = b.failHard;
        this.timeoutMs = b.timeoutMs;
        this.kdcAnchorsPem = b.kdcAnchorsPem;
        this.kdcCertName = b.kdcCertName;
        this.certLifetimeSeconds = b.certLifetimeSeconds;
        this.certSource = b.certSource;
        this.localCaCertPem = b.localCaCertPem;
        this.localCaKeyPem = b.localCaKeyPem;
        this.agentServiceUrl = b.agentServiceUrl;
        this.agentClientCertPem = b.agentClientCertPem;
        this.agentClientKeyPem = b.agentClientKeyPem;
        this.agentServerCaPem = b.agentServerCaPem;
    }

    /**
     * Fluent builder. Everything has a sane default, so tests set only what they care about and
     * new fields do not break existing call sites — the reason this exists instead of a widening
     * constructor.
     */
    static final class Builder {
        private String realm = "";
        private List<KdcAddress> kdcs = List.of();
        private String ticketKeyPath = DEFAULT_TICKET_KEY_PATH;
        private String principalAttribute = "";
        private String triggerClaim = "";
        private AsRepKeyMode asRepKeyMode = AsRepKeyMode.SESSION_KEY;
        private boolean failHard = false;
        private int timeoutMs = DEFAULT_TIMEOUT_MS;
        private String kdcAnchorsPem = "";
        private String kdcCertName = "";
        private int certLifetimeSeconds = DEFAULT_CERT_LIFETIME_SECONDS;
        private CertSource certSource = CertSource.LOCAL_CA;
        private String localCaCertPem = "";
        private String localCaKeyPem = "";
        private String agentServiceUrl = "";
        private String agentClientCertPem = "";
        private String agentClientKeyPem = "";
        private String agentServerCaPem = "";

        Builder realm(String v) { this.realm = v; return this; }
        Builder kdcs(List<KdcAddress> v) { this.kdcs = v; return this; }
        Builder ticketKeyPath(String v) { this.ticketKeyPath = v; return this; }
        Builder principalAttribute(String v) { this.principalAttribute = v; return this; }
        Builder triggerClaim(String v) { this.triggerClaim = v; return this; }
        Builder asRepKeyMode(AsRepKeyMode v) { this.asRepKeyMode = v; return this; }
        Builder failHard(boolean v) { this.failHard = v; return this; }
        Builder timeoutMs(int v) { this.timeoutMs = v; return this; }
        Builder kdcAnchorsPem(String v) { this.kdcAnchorsPem = v; return this; }
        Builder kdcCertName(String v) { this.kdcCertName = v; return this; }
        Builder certLifetimeSeconds(int v) { this.certLifetimeSeconds = v; return this; }
        Builder certSource(CertSource v) { this.certSource = v; return this; }
        Builder localCaCertPem(String v) { this.localCaCertPem = v; return this; }
        Builder localCaKeyPem(String v) { this.localCaKeyPem = v; return this; }
        Builder agentServiceUrl(String v) { this.agentServiceUrl = v; return this; }
        Builder agentClientCertPem(String v) { this.agentClientCertPem = v; return this; }
        Builder agentClientKeyPem(String v) { this.agentClientKeyPem = v; return this; }
        Builder agentServerCaPem(String v) { this.agentServerCaPem = v; return this; }

        KerberosRealmConfig build() { return new KerberosRealmConfig(this); }
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

    /** Empty means always attempt; otherwise the claim or scope value the Mac must send. */
    public String triggerClaim() {
        return triggerClaim;
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

    public String kdcAnchorsPem() {
        return kdcAnchorsPem;
    }

    /**
     * Hostname to expect in the KDC certificate, when it differs from the address we connect to.
     * Needed when {@code kerberosKdcHosts} holds IP addresses — an Active Directory KDC
     * certificate carries dNSName entries and no id-pkinit-san, so there is nothing for an IP to
     * match. Empty means verify against the connection address itself.
     */
    public String kdcCertName() {
        return kdcCertName;
    }

    public int certLifetimeSeconds() {
        return certLifetimeSeconds;
    }

    public CertSource certSource() {
        return certSource;
    }

    public String localCaCertPem() {
        return localCaCertPem;
    }

    public String localCaKeyPem() {
        return localCaKeyPem;
    }

    public String agentServiceUrl() {
        return agentServiceUrl;
    }

    public String agentClientCertPem() {
        return agentClientCertPem;
    }

    public String agentClientKeyPem() {
        return agentClientKeyPem;
    }

    public String agentServerCaPem() {
        return agentServerCaPem;
    }

    /**
     * Whether PKINIT can run: a way to verify the KDC's signed reply, plus a usable certificate
     * source for the configured kind. The passwordless flow is skipped when this is false.
     */
    public boolean pkinitConfigured() {
        if (kdcAnchorsPem.isEmpty()) {
            return false;
        }
        return switch (certSource) {
            case LOCAL_CA -> !localCaCertPem.isEmpty() && !localCaKeyPem.isEmpty();
            case AGENT_SERVICE -> !agentServiceUrl.isEmpty()
                    && !agentClientCertPem.isEmpty() && !agentClientKeyPem.isEmpty();
        };
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
        String triggerClaim = Optional.ofNullable(trimToNull(model.get("kerberosTriggerClaim")))
                .orElse("");
        boolean failHard = "fail".equalsIgnoreCase(trimToNull(model.get("kerberosFailureMode")));
        int timeoutMs = parsePositiveInt(model.get("kerberosTimeoutMs"), DEFAULT_TIMEOUT_MS);
        String localCaCertPem = Optional.ofNullable(trimToNull(model.get("kerberosLocalCaCert"))).orElse("");
        String localCaKeyPem = Optional.ofNullable(trimToNull(model.get("kerberosLocalCaKey"))).orElse("");
        String kdcAnchorsPem = Optional.ofNullable(trimToNull(model.get("kerberosKdcAnchors"))).orElse("");
        int certLifetimeSeconds = parsePositiveInt(model.get("kerberosCertLifetimeSeconds"),
                DEFAULT_CERT_LIFETIME_SECONDS);

        return Optional.of(new Builder()
                .realm(kerberosRealm)
                .kdcs(kdcs)
                .ticketKeyPath(ticketKeyPath)
                .principalAttribute(principalAttribute)
                .triggerClaim(triggerClaim)
                .asRepKeyMode(AsRepKeyMode.fromConfig(model.get("kerberosAsRepKeyMode")))
                .failHard(failHard)
                .timeoutMs(timeoutMs)
                .kdcAnchorsPem(kdcAnchorsPem)
                .kdcCertName(Optional.ofNullable(trimToNull(model.get("kerberosKdcCertName"))).orElse(""))
                .certLifetimeSeconds(certLifetimeSeconds)
                .certSource(CertSource.fromConfig(model.get("kerberosCertSource")))
                .localCaCertPem(localCaCertPem)
                .localCaKeyPem(localCaKeyPem)
                .agentServiceUrl(Optional.ofNullable(trimToNull(model.get("kerberosAgentServiceUrl"))).orElse(""))
                .agentClientCertPem(Optional.ofNullable(trimToNull(model.get("kerberosAgentClientCert"))).orElse(""))
                .agentClientKeyPem(Optional.ofNullable(trimToNull(model.get("kerberosAgentClientKey"))).orElse(""))
                .agentServerCaPem(Optional.ofNullable(trimToNull(model.get("kerberosAgentServerCa"))).orElse(""))
                .build());
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
