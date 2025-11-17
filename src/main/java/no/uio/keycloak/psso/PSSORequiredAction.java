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

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;


public class PSSORequiredAction implements RequiredActionProvider, RequiredActionFactory, CredentialRegistrator, CredentialAction{

    public static final String PROVIDER_ID = "psso-required-action";
    private static final Logger logger = Logger.getLogger(PSSORequiredAction.class);

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        // Load EduMFA realm-level configuration

    }

    @Override
    public void processAction(RequiredActionContext context) {

        context.failure();
    }


    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.NOT_SUPPORTED;
    }
    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }


    @Override
    public String getId() {
        return PSSORequiredAction.PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Platform Single Sign-on for macOS devices";
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }
    @Override
    public String getCredentialType(KeycloakSession session, AuthenticationSessionModel authenticationSession) {
        return UserPSSOCredentialModel.TYPE;
    }

}