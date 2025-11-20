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

package no.uio.keycloak.psso;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.infinispan.Cache;
import java.util.UUID;
/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
public class NonceService {

    private static final long NONCE_TTL_MS = 60_000; // 1 minute
    private final Cache<String, NonceEntry> nonceCache;
    private static final Logger logger = Logger.getLogger(NonceService.class);

    public NonceService(KeycloakSession session) {
        var infinispan = session.getProvider(InfinispanConnectionProvider.class);
        this.nonceCache = infinispan.getCache("work");
    }

    public String createNonce(String clientRequestId) {
        String nonce = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + NONCE_TTL_MS;

        nonceCache.put(nonce, new NonceEntry(clientRequestId, expiresAt));
        return nonce;
    }

    public boolean validateNonce(String nonce, String clientRequestId) {
        NonceEntry entry = nonceCache.remove(nonce); // consume once
        logger.debug("Nonce to validate: " + nonce + ", client-request-id: " + clientRequestId + ", entry: " + entry);

        logger.debug("Nonce entry expiresAt: " + entry.expiresAt);
        logger.debug("Nonce entry now: " + System.currentTimeMillis());

        if (System.currentTimeMillis() > entry.expiresAt) {
            logger.debug("Nonce expired");
            return false;
        }
        // Verify it matches the same client-request-id
        return entry.clientRequestId.equals(clientRequestId);
    }

    private static class NonceEntry implements java.io.Serializable {
        final String clientRequestId;
        final long expiresAt;

        NonceEntry(String clientRequestId, long expiresAt) {
            this.clientRequestId = clientRequestId;
            this.expiresAt = expiresAt;
        }
    }
}