package no.uio.keycloak.psso.kerberos;

import org.keycloak.models.UserModel;

/**
 * What a {@link KerberosTgtProvider} needs to obtain a ticket.
 *
 * {@code password} is only populated for the Platform SSO password grant, where the cleartext
 * password arrives inside the device-signed assertion. Every other grant (Secure Enclave,
 * refresh, OIDC token exchange) leaves it null and requires a credential-less provider.
 */
public record KerberosTgtRequest(
        String principal,
        String password,
        UserModel user
) {
    public boolean hasPassword() {
        return password != null && !password.isEmpty();
    }
}
