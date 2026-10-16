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

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.LastReq;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlags;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AsExchangeTest {

    private static final String REALM = "IPA.EXAMPLE.COM";

    /**
     * MIT krb5 — and therefore FreeIPA — tags the AS-REP enc-part [APPLICATION 26], which RFC 4120
     * §5.4.2 explicitly tells implementers to tolerate. Observed against a real FreeIPA KDC.
     */
    @Test
    void acceptsEncPartTaggedAsEncTgsRepPart() throws Exception {
        byte[] asRepTagged = KrbCodec.encode(sampleEncPart());
        assertEquals(0x79, asRepTagged[0] & 0xFF, "sanity: Kerby encodes EncASRepPart as [APPLICATION 25]");

        byte[] tgsRepTagged = asRepTagged.clone();
        tgsRepTagged[0] = (byte) 0x7A;

        EncAsRepPart decoded = AsExchange.decodeEncAsRepPart(tgsRepTagged);

        assertEquals(REALM, decoded.getSrealm());
        assertEquals(4242, decoded.getNonce());
    }

    @Test
    void stillAcceptsTheSpecCorrectTag() throws Exception {
        EncAsRepPart decoded = AsExchange.decodeEncAsRepPart(KrbCodec.encode(sampleEncPart()));
        assertEquals(REALM, decoded.getSrealm());
    }

    @Test
    void rejectsGenuinelyCorruptEncParts() {
        assertThrows(KrbException.class,
                () -> AsExchange.decodeEncAsRepPart(new byte[]{0x79, 0x05, 0x01, 0x02, 0x03}));
        assertThrows(KrbException.class,
                () -> AsExchange.decodeEncAsRepPart(new byte[0]));
    }

    private static EncAsRepPart sampleEncPart() throws KrbException {
        PrincipalName tgs = new PrincipalName("krbtgt/" + REALM);
        tgs.setRealm(REALM);

        EncAsRepPart encPart = new EncAsRepPart();
        encPart.setKey(EncryptionHandler.random2Key(EncryptionType.AES256_CTS_HMAC_SHA1_96));
        encPart.setLastReq(new LastReq());
        encPart.setNonce(4242);
        encPart.setFlags(new TicketFlags());
        encPart.setAuthTime(new KerberosTime(1771000000000L));
        encPart.setEndTime(new KerberosTime(1771003600000L));
        encPart.setSrealm(REALM);
        encPart.setSname(tgs);
        return encPart;
    }
}
