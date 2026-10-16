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
 * Obtains a TGT from a KDC on a user's behalf.
 *
 * Implementations differ only in how they prove the user's identity to the KDC: a password-derived
 * AS-REQ today, PKINIT with a short-lived certificate next. Everything downstream — re-encrypting
 * the AS-REP enc-part and emitting Apple's sub-dictionary — is shared in {@link AsRepPackager}.
 */
public interface KerberosTgtProvider {

    /** Human-readable name used in log lines. */
    String name();

    KerberosTgt obtain(KerberosTgtRequest request) throws Exception;
}
