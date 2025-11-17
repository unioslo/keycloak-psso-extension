/* Copyright 2025 University of Oslo, Norway
 # This file is part of Cerebrum.
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

package no.uio.keycloak.psso;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;



public class UserPSSOCredentialProviderFactory implements CredentialProviderFactory<UserPSSOCredentialProvider> {
    public static final String PROVIDER_ID =  "psso";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new UserPSSOCredentialProvider(session);
    }

}