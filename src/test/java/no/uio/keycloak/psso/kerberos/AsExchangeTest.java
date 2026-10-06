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
