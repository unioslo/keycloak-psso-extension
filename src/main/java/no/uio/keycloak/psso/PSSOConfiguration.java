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
package no.uio.keycloak.psso;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.ui.extend.UiTabProvider;
import org.keycloak.services.ui.extend.UiTabProviderFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PSSOConfiguration implements UiTabProvider, UiTabProviderFactory<ComponentModel> {
    private KeycloakSession session;

    @Override
    public String getId() {
        return "Platform Single Sign-on";
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        builder.property()
                .name("requireRegistrationToken")
                .label("Require Registration Token")
                .helpText("Require Registration Token for device registration. If not required, a user token will be required.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name("registrationToken")
                .label("Registration Token")
                .helpText("Registration Token for device registration")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()
                .property()
                .name("clientIDOIDCFlow")
                .label("Client ID for OIDC flow")
                .helpText("Client ID for OIDC flow")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("clientSecretOIDCFlow")
                .label("Client Secret for OIDC flow")
                .helpText("Client Secret for OIDC flow")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()
                .property()
                .name("clientIDforCardRegistration")
                .label("Client ID for card registration")
                .helpText("Client ID for card registration")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("psso-card")
                .add()
                .property()
                .name("caKeysForCardValidation")
                .label("CA Keys for card validation")
                .helpText("CA Keys for card validation. Users registering cards with keys will have hose validated against one of these keys. "
                        + "Paste one or more certificates as PEM, one after the other: a bundle rather than a single "
                        + "certificate so an issuer key can be rotated without every card issued under the old one "
                        + "losing the ability to enroll. Key ids are derived from the keys, never entered by hand.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name("cardSerialPrefixes")
                .label("Accepted card serial prefixes")
                .helpText("Comma-separated, e.g. \"CPLC:\". Leave empty to accept any card. "
                        + "provision-card.sh falls back to a \"SIM:\" identity when a chip reports a blank CPLC, "
                        + "so an empty list lets a simulated card enroll against a real account.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("cardEnrollMaxAgeDays")
                .label("Maximum age of a card issuance record")
                .helpText("Reject issuance records older than this many days. Signatures do not expire on their own, "
                        + "so without a bound a record for a card decommissioned two years ago stays enrollable.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("30")
                .add()
                .property()
                .name("kerberosEnabled")
                .label("Issue Kerberos TGT")
                .helpText("Include a Kerberos ticket-granting ticket in the Platform SSO login response, "
                        + "so Macs hold a usable TGT straight after login. Requires the companion SSO "
                        + "extension to declare kerberosTicketMappings; without that the ticket is "
                        + "silently discarded by macOS.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name("kerberosRealm")
                .label("Kerberos realm")
                .helpText("Upper-case realm name, e.g. AD.EXAMPLE.COM.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kerberosKdcHosts")
                .label("KDC hosts")
                .helpText("Comma-separated host or host:port list, tried in order. Port defaults to 88. "
                        + "Contacted over TCP, since a TGT carrying a PAC routinely exceeds a UDP datagram.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kerberosPrincipalAttribute")
                .label("Principal user attribute")
                .helpText("User attribute holding the Kerberos principal. Leave empty to use the username. "
                        + "The realm is appended when the value has no @.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kerberosTriggerClaim")
                .label("Require claim or scope to issue a TGT")
                .helpText("Leave empty to attempt a TGT on every password login. If set (e.g. "
                        + "fetch_kerberos_tgt), a ticket is only fetched when the Mac's SSO extension "
                        + "sends that name either as a custom login-request claim or as an extra scope. "
                        + "Lets MDM enable Kerberos per machine, and spares off-domain Macs the KDC "
                        + "connect timeout on every login.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kerberosTicketKeyPath")
                .label("Ticket key path")
                .helpText("Key in the login response holding the ticket. Must match ticketKeyPath in the "
                        + "SSO extension's Kerberos mapping.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("login_tgt")
                .add()
                .property()
                .name("kerberosLocalCaCert")
                .label("PKINIT CA certificate")
                .helpText("PEM certificate of the CA that mints per-login PKINIT client certificates. "
                        + "Enables Kerberos for passwordless logins (Secure Enclave). On FreeIPA, install "
                        + "this CA as a KDC trust anchor (ipa-cacert-manage install + ipa-certupdate) and "
                        + "scope it with a certmap rule. Never add this CA to Active Directory's NTAuth "
                        + "store - the AD path uses an enrollment agent instead.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name("kerberosLocalCaKey")
                .label("PKINIT CA private key")
                .helpText("PEM private key (PKCS#8 or legacy RSA/EC form, unencrypted) for the PKINIT CA. "
                        + "Paste the full PEM including the BEGIN/END lines. For production, put the key in "
                        + "the Keycloak vault and reference it here as ${vault.kerberos-pkinit-ca-key} "
                        + "instead - a vault reference works in this field too. Treat this as highly "
                        + "sensitive: it can mint a PKINIT certificate for any principal the certmap rule "
                        + "matches.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .secret(true)
                .add()
                .property()
                .name("kerberosKdcAnchors")
                .label("KDC trust anchors")
                .helpText("PEM bundle of the CA(s) that issued the KDC's own PKINIT certificate, used to "
                        + "verify the KDC's signed Diffie-Hellman reply. On FreeIPA this is the IPA CA; "
                        + "on Active Directory, the CA that issued the domain controller certificates.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name("kerberosKdcCertName")
                .label("Expected KDC certificate hostname")
                .helpText("Leave empty to verify the KDC's certificate against the address in KDC hosts. "
                        + "Set this when KDC hosts holds IP addresses: an Active Directory KDC certificate "
                        + "carries dNSName entries and no pkinit SAN, so an IP can never match. FreeIPA "
                        + "KDC certificates usually carry a pkinit SAN, which matches on the realm and "
                        + "needs no hostname.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kerberosCertLifetimeSeconds")
                .label("PKINIT certificate lifetime (seconds)")
                .helpText("Validity of each per-login client certificate beyond clock-skew backdating. "
                        + "It only needs to outlive one AS exchange. (Local CA source only; with an "
                        + "enrollment agent the issuing CA's template decides the lifetime.)")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("60")
                .add()
                .property()
                .name("kerberosCertSource")
                .label("PKINIT certificate source")
                .helpText("Where passwordless-login certificates come from. \"local-ca\" (FreeIPA): "
                        + "Keycloak mints them from the CA above. \"agent-service\" (Active Directory): "
                        + "Keycloak sends a CSR to an enrollment-agent service that has AD CS issue them. "
                        + "The local-ca fields apply to the former, the agent fields below to the latter.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("local-ca", "agent-service")
                .defaultValue("local-ca")
                .add()
                .property()
                .name("kerberosAgentServiceUrl")
                .label("Enrollment agent service URL")
                .helpText("HTTPS endpoint of the Windows enrollment-agent service (agent-service source). "
                        + "Keycloak POSTs a CSR and receives an AD CS-issued certificate; the private key "
                        + "never leaves Keycloak.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kerberosAgentClientCert")
                .label("Enrollment agent client certificate")
                .helpText("PEM client certificate Keycloak presents to the agent service for mutual TLS.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name("kerberosAgentClientKey")
                .label("Enrollment agent client key")
                .helpText("PEM private key for the mutual-TLS client certificate (unencrypted; a "
                        + "${vault.key} reference works too). This authenticates Keycloak to the agent "
                        + "and is not a CA key, but keep it protected.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .secret(true)
                .add()
                .property()
                .name("kerberosAgentServerCa")
                .label("Enrollment agent server CA")
                .helpText("PEM CA bundle used to verify the agent service's own TLS certificate. Leave "
                        + "empty to use the JVM default trust store; pinning a private CA here is safer.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name("kerberosAsRepKeyMode")
                .label("AS-REP key mode")
                .helpText("Which key the AS-REP enc-part is re-encrypted under. \"session-key\" publishes the "
                        + "ticket session key and works whether macOS treats the field as the reply key or "
                        + "the session key, so leave it unless a Mac proves otherwise.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("session-key", "random-reply-key")
                .defaultValue("session-key")
                .add()
                .property()
                .name("kerberosFailureMode")
                .label("On TGT failure")
                .helpText("\"ignore\" returns the login response without a ticket, so a KDC outage never "
                        + "blocks sign-in. \"fail\" rejects the login instead.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("ignore", "fail")
                .defaultValue("ignore")
                .add()
                .property()
                .name("kerberosTimeoutMs")
                .label("KDC timeout (ms)")
                .helpText("Per-KDC timeout. Kept short: this sits in the login path.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("5000")
                .add();


        return builder.build();
    }

    @Override
    public String getPath() {
        return "/:realm/realm-settings/:tab";
    }

    @Override
    public Map<String, String> getParams() {
        Map<String, String> params = new HashMap<>();
        params.put("tab", "psso");
        return params;
    }

}
