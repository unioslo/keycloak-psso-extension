package no.uio.keycloak.psso;

import org.keycloak.models.KeycloakSession;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.infinispan.Cache;
import java.util.UUID;

public class NonceService {

    private static final long NONCE_TTL_MS = 60_000; // 1 minute
    private final Cache<String, NonceEntry> nonceCache;

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

        if (entry == null) return false;
        if (System.currentTimeMillis() > entry.expiresAt) return false;

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