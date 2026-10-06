package no.uio.keycloak.psso.kerberos;

/**
 * Obtains a TGT from a KDC on a user's behalf.
 *
 * Implementations differ only in how they prove the user's identity to the KDC: a password-derived
 * AS-REQ today, PKINIT with a short-lived certificate next. Everything downstream — re-encrypting
 * the AS-REP enc-part and emitting Apple's sub-dictionary — is shared in {@link AsRepPackager}.
 */
public interface KerberosTgtProvider {

    /** Human-readable name used in log lines. */
    String name();

    KerberosTgt obtain(KerberosTgtRequest request) throws Exception;
}
