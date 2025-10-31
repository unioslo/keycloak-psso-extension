/* Copyright 2025 University of Oslo, Norway
 # This file is part of Cerebrum.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension  is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with Cerebrum; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/
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