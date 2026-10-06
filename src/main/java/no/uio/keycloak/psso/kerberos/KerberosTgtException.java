package no.uio.keycloak.psso.kerberos;

/**
 * Raised only when the realm is configured with {@code kerberosFailureMode=fail}. Under the
 * default {@code ignore} policy a failure to obtain a ticket is logged and the login response is
 * returned without one.
 */
public class KerberosTgtException extends RuntimeException {

    public KerberosTgtException(String message, Throwable cause) {
        super(message, cause);
    }
}
