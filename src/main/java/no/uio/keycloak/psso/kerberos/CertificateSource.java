package no.uio.keycloak.psso.kerberos;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Provides the short-lived certificate and private key PKINIT signs with.
 *
 * This is the only directory-aware seam in the PKINIT path. FreeIPA scopes trust at the KDC via
 * certmap rules, so a small CA held by Keycloak is acceptable there ({@link LocalCaIssuer}).
 * Active Directory scopes trust at the CA instead, so its implementation will be a thin mTLS
 * client talking to a Windows enrollment-agent service — the exchange code never changes.
 */
public interface CertificateSource {

    /** Human-readable name used in log lines. */
    String name();

    /**
     * Issues (or obtains) a certificate binding {@code clientName@realm}, valid for roughly the
     * duration of one AS exchange. Nothing is persisted; the key pair lives for one login.
     */
    IssuedIdentity issueFor(String clientName, String realm) throws Exception;

    record IssuedIdentity(X509Certificate certificate, PrivateKey privateKey) { }
}
