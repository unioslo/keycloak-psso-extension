package no.uio.keycloak.psso.token;

public class IssuedTokens {
    public final String accessToken;
    public final String idToken;
    public final String refreshToken;

    public IssuedTokens(String accessToken, String idToken, String refreshToken) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
    }
}
