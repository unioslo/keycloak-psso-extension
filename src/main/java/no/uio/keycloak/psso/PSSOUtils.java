package no.uio.keycloak.psso;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ui.extend.UiTabProvider;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public  class PSSOUtils {

    static Logger logger = Logger.getLogger(PSSOUtils.class);

    // Shared client, reused for the lifetime of the provider. Building a new HttpClient per
    // request leaks connections/threads (each instance owns a keep-alive pool + selector thread
    // that is only reclaimed by GC), which starved Keycloak's worker pool and caused intermittent
    // timeouts on the (self-directed) PAR call. HTTP/1.1 avoids flaky HTTP/2 upgrade negotiation.
    private static final HttpClient PAR_CLIENT = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

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

        String authUrl;

        String params = "client_id=" + clientId
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&response_type=code&scope="+URLEncoder.encode(scope, StandardCharsets.UTF_8)
                + "&state=" + state
                + "&nonce=" + nonce;

        // logger.info("Platform SSO: STATE: Redirecting to IdP: " + state);
        // logger.info("Platform SSO: Nonce: Redirecting to IdP: " + nonce);
        logger.debug("Platform SSO: parameters to be included in the url: " + params);
        // We make a PAR request to the idp
        // The idp will return a request_uri that we can use to redirect the user to the idp
        // This allows the client to remain confidential and not expose the client secret
            params = params+"&client_secret="+pssoConfig.get("clientSecretOIDCFlow");
            String url = baseUrl + "/realms/" + realm.getName() + "/protocol/openid-connect/ext/par/request";
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(params));

            HttpRequest request = requestBuilder.build();
            try {
                java.net.http.HttpResponse<String> response = PAR_CLIENT.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
                logger.info("Platform SSO: Response status: "+response.statusCode());
                if (response.statusCode() != 201 && response.statusCode() != 200) {
                    logger.error("Platform SSO: Error sending PAR request to the idp. Status code: " + response.statusCode());
                    logger.error("Platform SSO: Response body: " + response.body());
                    throw new RuntimeException("Platform SSO: There was an error sending a PAR request to the idp.");
                }
                logger.info("Platform SSO: PAR request sent to the idp.");
                JSONObject jsonResponse = new JSONObject(response.body());
                String requestUri = jsonResponse.getString("request_uri");
                authUrl = authorizationUrl + "?request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8)
                        + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                        + "&login_hint=" + URLEncoder.encode(loginHint, StandardCharsets.UTF_8);
            }catch (Exception e){
                logger.error("Platform SSO: Error sending PAR request to the idp. " + e.getMessage());
               throw new RuntimeException("Platform SSO: There was an error sending a PAR request to the idp: "+e);

            }



        logger.info("Platform SSO: Redirecting to IdP: " + authUrl);
        return Response.seeOther(URI.create(authUrl)).build();

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


}
