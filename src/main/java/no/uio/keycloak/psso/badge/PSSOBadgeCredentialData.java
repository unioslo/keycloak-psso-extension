/* Copyright 2025 University of Oslo, Norway
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

package no.uio.keycloak.psso.badge;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The non-secret half of a badge credential, serialized into {@code credentialData}.
 * The token hash lives in {@code secretData} instead — see {@link PSSOBadgeSecretData}.
 *
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PSSOBadgeCredentialData {

    private String label;
    private int badgeSequence;
    private String issuedBy;

    public PSSOBadgeCredentialData() {
    }

    public PSSOBadgeCredentialData(String label, int badgeSequence, String issuedBy) {
        this.label = label;
        this.badgeSequence = badgeSequence;
        this.issuedBy = issuedBy;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    /**
     * Increments on every reissue for the same pupil, and is what the scanned payload is
     * matched against. An int rather than the credential UUID: far cheaper in QR modules,
     * and it gives the "badge #3 was issued, #2 was reported lost" audit trail.
     */
    public int getBadgeSequence() {
        return badgeSequence;
    }

    public void setBadgeSequence(int badgeSequence) {
        this.badgeSequence = badgeSequence;
    }

    /** Username of the teacher or admin who issued the badge. */
    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }
}
