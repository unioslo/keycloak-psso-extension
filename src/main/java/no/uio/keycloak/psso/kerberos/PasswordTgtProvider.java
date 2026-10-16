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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * Obtains a TGT with an ordinary password-based AS exchange.
 *
 * Only usable for the Platform SSO password grant, where the cleartext password is present in the
 * device-signed assertion. The exchange itself is driven by {@link AsExchange} rather than Kerby's
 * client, which cannot honour a KDC-supplied salt.
 */
public final class PasswordTgtProvider implements KerberosTgtProvider {

    private static final Logger logger = Logger.getLogger(PasswordTgtProvider.class);

    private final KerberosRealmConfig config;

    public PasswordTgtProvider(KerberosRealmConfig config) {
        this.config = config;
    }

    @Override
    public String name() {
        return "password";
    }

    @Override
    public KerberosTgt obtain(KerberosTgtRequest request) throws KrbException, IOException {
        if (!request.hasPassword()) {
            throw new KrbException("No password available for principal " + request.principal());
        }

        String clientName = clientName(request.principal());
        IOException lastUnreachable = null;

        for (KerberosRealmConfig.KdcAddress kdc : config.kdcs()) {
            try {
                logger.debugf("Platform SSO: Requesting TGT for %s from %s:%d.",
                        request.principal(), kdc.host(), kdc.port());

                TgtTicket tgt = new AsExchange(config)
                        .requestTgtWithPassword(clientName, request.password(), kdc);

                return AsRepPackager.pack(tgt, config.asRepKeyMode());

            } catch (IOException e) {
                // Transport only. A protocol or credential error (KrbException) would repeat
                // against every KDC, so it propagates immediately instead.
                logger.warnf("Platform SSO: KDC %s:%d unreachable (%s); trying next.",
                        kdc.host(), kdc.port(), e.getMessage());
                lastUnreachable = e;
            }
        }

        if (lastUnreachable != null) {
            throw lastUnreachable;
        }
        throw new KrbException("No KDC configured for realm " + config.realm());
    }

    /** AsExchange applies the configured realm itself, so strip any "@REALM" suffix. */
    private static String clientName(String principal) {
        int at = principal.lastIndexOf('@');
        return at > 0 ? principal.substring(0, at) : principal;
    }
}
