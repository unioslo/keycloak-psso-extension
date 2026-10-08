package no.uio.keycloak.psso.kerberos;

/**
 * Which key the AS-REP enc-part is re-encrypted under before being handed to macOS.
 *
 * Apple documents the login response as carrying both a base-64 AS-REP ("messageBuffer") and a
 * separate "sessionKey", but does not say whether that key is the AS-REP <em>reply key</em> (the
 * one that decrypts enc-part) or the <em>ticket session key</em> carried inside enc-part. Entra's
 * published mapping names the field "clientKey", which points at the reply-key reading.
 *
 * {@link #SESSION_KEY} sidesteps the ambiguity: the enc-part is re-encrypted under the ticket
 * session key itself, so reply key == session key and both readings yield a working credential.
 * That is why it is the default. The ticket inside the AS-REP is never touched and the KDC never
 * sees the re-encrypted message, so this stays protocol-safe.
 *
 * Resolved empirically against macOS 27.2 and FreeIPA: Heimdal feeds this key to its
 * ENCRYPTED_TIMESTAMP pre-auth mech and then decrypts the enc-part with it, so Apple means the
 * <em>reply key</em> — the Entra "clientKey" naming was the correct hint. Sending the bare ticket
 * session key without re-encrypting would therefore have failed; the hedge is load-bearing, not
 * merely defensive.
 */
public enum AsRepKeyMode {

    /** Re-encrypt under the ticket session key, and publish that key. Satisfies both readings. */
    SESSION_KEY,

    /** Re-encrypt under a fresh random key of the same type, and publish that key instead. */
    RANDOM_REPLY_KEY;

    public static AsRepKeyMode fromConfig(String value) {
        if (value == null || value.isBlank()) {
            return SESSION_KEY;
        }
        return switch (value.trim().toLowerCase()) {
            case "random-reply-key" -> RANDOM_REPLY_KEY;
            default -> SESSION_KEY;
        };
    }
}
