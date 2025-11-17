package no.uio.keycloak.psso.token;

import org.keycloak.models.KeycloakSession;

public class PSSOTokenService {
/*
    private final KeycloakSession session;
    private final JWSDecoder jwsDecoder;
    private final AssertionValidator assertionValidator;
    private final TokenIssuer tokenIssuer;
    private final JWEEncryptor jweEncryptor;

    public PSSOTokenService(KeycloakSession session) {
        this.session = session;
        this.jwsDecoder = new JWSDecoder(session);
        this.assertionValidator = new AssertionValidator(session);
        this.tokenIssuer = new TokenIssuer(session);
        this.jweEncryptor = new JWEEncryptor(session);
    }

    public String handleLoginRequest(String assertionJWS) {

        // 1. Parse + verify ES256 signature
        var claims = jwsDecoder.parseAndVerify(assertionJWS);

        // 2. Validate claims (nonce, iat, exp, aud, iss, sub, device key, etc.)
        var device = assertionValidator.validate(claims);

        // 3. Issue id_token + refresh_token
        var tokenJson = tokenIssuer.issueTokens(device.getUser());

        // 4. Encrypt token response using device encryption key
        return jweEncryptor.encryptResponse(tokenJson, device);
    }

 */
}
