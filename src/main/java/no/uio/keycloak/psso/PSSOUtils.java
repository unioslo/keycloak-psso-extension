package no.uio.keycloak.psso;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ui.extend.UiTabProvider;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public  class PSSOUtils {

    static Logger logger = Logger.getLogger(PSSOUtils.class);
    public static Response redirectIdp(KeycloakSession session, String state, String nonce, String scope, String loginHint, String client_id) {
        // Otherwise -> force redirect to IdP
        RealmModel realm = session.getContext().getRealm();
        ComponentModel pssoConfig = realm.getComponentsStream(realm.getId(), UiTabProvider.class.getName())
                .filter(c -> "Platform Single Sign-on".equals(c.getProviderId()))
                .findFirst()
                .orElse(null);
        if (pssoConfig == null){
            return Response.status(Response.Status.NOT_FOUND)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }

        String clientId = pssoConfig.get("clientIDOIDCFlow");
        if (!client_id.equals(clientId)) {
            logger.error("Platform SSO: Client ID mismatch. Expected: " + clientId + " Received: " + client_id);
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type("application/platformsso-login-response+jwt")
                    .build();
        }

        String baseUrl = session.getContext().getUri().getBaseUri().toString();
        baseUrl = baseUrl.replaceAll("/$", "");
        String authorizationUrl = baseUrl + "/realms/" + realm.getName() + "/protocol/openid-connect/auth";
        String redirectUri = baseUrl + "/realms/" + realm.getName() + "/psso/oidcflowcallback";

        // Generate PKCE parameters
        String codeVerifier = generateCodeVerifier();

        String authUrl;

        String params = "client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&response_type=code&scope="+URLEncoder.encode(scope, StandardCharsets.UTF_8)
                + "&state=" + state
                + "&nonce=" + nonce;

        logger.debug("Platform SSO: parameters to be included in the url: " + params);
        // We make a PAR request to the idp
        // The idp will return a request_uri that we can use to redirect the user to the idp
        // This allows the client to remain confidential and not expose the client secret
            params = params+"&client_secret="+pssoConfig.get("clientSecretOIDCFlow");
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(60))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/realms/" + realm.getName() + "/protocol/openid-connect/ext/par/request"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .timeout(Duration.ofSeconds(70))
                    .POST(HttpRequest.BodyPublishers.ofString(params));

            HttpRequest request = requestBuilder.build();
            try {
                logger.info("Platform SSO: Sending PAR request to the idp.");
                java.net.http.HttpResponse<String> response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 201 && response.statusCode() != 200) {
                    logger.error("Platform SSO: Error sending PAR request to the idp. Status code: " + response.statusCode());
                    logger.error("Platform SSO: Response body: " + response.body());
                    throw new RuntimeException("Platform SSO: There was an error sending a PAR request to the idp.");
                }
                logger.info("Platform SSO: PAR request sent to the idp.");
                JSONObject jsonResponse = new JSONObject(response.body());
                String requestUri = jsonResponse.getString("request_uri");
                authUrl = authorizationUrl + "?request_uri="+ requestUri+ "&client_id="+ clientId+"&login_hint="+loginHint;
            }catch (Exception e){
                logger.error("Platform SSO: Error sending PAR request to the idp. " + e.getMessage());
               throw new RuntimeException("Platform SSO: There was an error sending a PAR request to the idp: "+e);

            }



        logger.info("Platform SSO: Redirecting to IdP: " + authUrl);
        return Response.seeOther(URI.create(authUrl)).build();

    }

    /**
     * Generates a cryptographically secure random code verifier for PKCE.
     * The verifier is a 43-128 character base64url-encoded string.
     */
    private static String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32]; // 32 bytes = 43 chars when base64url encoded
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * Generates a code challenge from a code verifier using SHA256.
     * The challenge is the base64url-encoded SHA256 hash of the verifier.
     */
    private static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate code challenge", e);
        }
    }

    /**
     * Generates a cryptographically secure random nonce for OIDC.
     * The nonce is a base64url-encoded random string used to prevent replay attacks.
     */
    static String generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonceBytes = new byte[32]; // 32 bytes of randomness
        secureRandom.nextBytes(nonceBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    }

     static Map<String, String> parseQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=", 2);
                String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                String value = pair.length > 1 ? URLDecoder.decode(pair[1],
                        StandardCharsets.UTF_8) : "";
                params.put(key, value);
            }
        }
        return params;
    }

    static JsonNode parseJson(String jsonString) {
        try {
            return new ObjectMapper().readTree(jsonString);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON", e);
        }
    }

    static boolean verifySignature (String signature, String payload, String key) {
        return false;
    }

}
