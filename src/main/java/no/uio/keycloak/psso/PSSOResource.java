package no.uio.keycloak.psso;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.infinispan.Cache;


import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;


import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;


@Path("")
public class PSSOResource {

    private final KeycloakSession session;
    Logger logger = Logger.getLogger(PSSOResource.class);

    public PSSOResource(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Path("/nonce")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatus(
            @FormParam("grant_type") @DefaultValue("") String grantType,
            @FormParam("client-request-id") @DefaultValue("") String clientRequestId) {
        if (clientRequestId == null || clientRequestId.isEmpty() || !grantType.equals("srv_challenge")) {
           String error = "Missing grant type and/or client request id";

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", error))
                    .build();
        }

        NonceService nonceService = new NonceService(session);
        String nonce = nonceService.createNonce(clientRequestId);
        return Response.ok(Map.of("nonce", nonce)).build();
    }
}