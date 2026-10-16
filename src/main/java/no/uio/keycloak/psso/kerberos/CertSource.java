/* Copyright 2026 University of Oslo, Norway
 # This file is part of the Keycloak Platform SSO Extension codebase.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/
package no.uio.keycloak.psso.kerberos;

/**
 * Where PKINIT client certificates come from, which is the one part of the flow that differs by
 * directory.
 *
 * {@link #LOCAL_CA} — Keycloak holds a small CA and mints certs itself ({@link LocalCaIssuer}).
 * Acceptable on FreeIPA, where trust is scoped at the KDC by a certmap rule.
 *
 * {@link #AGENT_SERVICE} — Keycloak sends a CSR to an external enrollment-agent service that gets
 * the certificate issued by an existing CA ({@link AgentServiceClient}). This is the Active
 * Directory path: AD cannot scope an NTAuth CA, so the agent + AD CS's Restricted Enrollment Agent
 * feature provide the scoping instead.
 */
public enum CertSource {

    LOCAL_CA,
    AGENT_SERVICE;

    public static CertSource fromConfig(String value) {
        if (value == null || value.isBlank()) {
            return LOCAL_CA;
        }
        return switch (value.trim().toLowerCase()) {
            case "agent-service" -> AGENT_SERVICE;
            default -> LOCAL_CA;
        };
    }
}
