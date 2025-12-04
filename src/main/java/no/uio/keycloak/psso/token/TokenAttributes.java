package no.uio.keycloak.psso.token;

public class TokenAttributes {

    String username;
    String sid;

    public TokenAttributes(String username, String sid) {
        this.username = username;
        this.sid = sid;
    }

}
