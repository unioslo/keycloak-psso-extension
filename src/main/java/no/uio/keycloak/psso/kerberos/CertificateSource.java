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
