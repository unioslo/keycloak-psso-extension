package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.LastReq;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlags;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import no.uio.keycloak.psso.token.JweBuilder;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Round-trips the AS-REP we hand to macOS: pack a ticket, then decode and decrypt the result using
 * only the fields Apple's mapping exposes. If these pass, a Mac has everything it needs to import
 * the credential.
 */
class AsRepPackagerTest {

    private static final String REALM = "AD.EXAMPLE.COM";
    private static final String USER = "alice";
    private static final long END_TIME = 1771000000000L;

    @Test
    void sessionKeyModeMakesReplyKeyAndSessionKeyIdentical() throws Exception {
        EncryptionKey sessionKey = EncryptionHandler.random2Key(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        TgtTicket tgt = syntheticTgt(sessionKey);

        KerberosTgt packaged = AsRepPackager.pack(tgt, AsRepKeyMode.SESSION_KEY);

        // The published key must be the ticket session key itself, which is what makes the
        // response correct under either reading of Apple's "sessionKey" field.
        assertArrayEquals(sessionKey.getKeyData(), packaged.sessionKey());
        assertEquals(EncryptionType.AES256_CTS_HMAC_SHA1_96.getValue(), packaged.encryptionKeyType());

        EncAsRepPart recovered = decryptEncPart(packaged);
        assertArrayEquals(sessionKey.getKeyData(), recovered.getKey().getKeyData());
    }

    @Test
    void randomReplyKeyModePublishesTheKeyThatActuallyDecrypts() throws Exception {
        EncryptionKey sessionKey = EncryptionHandler.random2Key(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        TgtTicket tgt = syntheticTgt(sessionKey);

        KerberosTgt packaged = AsRepPackager.pack(tgt, AsRepKeyMode.RANDOM_REPLY_KEY);

        assertFalse(Arrays.equals(sessionKey.getKeyData(), packaged.sessionKey()),
                "random-reply-key mode must not publish the ticket session key");

        // The published key still decrypts enc-part, and the real session key is inside it.
        EncAsRepPart recovered = decryptEncPart(packaged);
        assertArrayEquals(sessionKey.getKeyData(), recovered.getKey().getKeyData());
    }

    @Test
    void namesMatchApplesExpectedFormat() throws Exception {
        KerberosTgt packaged = AsRepPackager.pack(
                syntheticTgt(EncryptionHandler.random2Key(EncryptionType.AES256_CTS_HMAC_SHA1_96)),
                AsRepKeyMode.SESSION_KEY);

        // Apple's examples carry bare names; PrincipalName.getName() would append "@REALM".
        assertEquals(USER, packaged.clientName());
        assertEquals("krbtgt/" + REALM, packaged.serviceName());
        assertEquals(REALM, packaged.realm());
        assertEquals(END_TIME, packaged.endTimeMillis());
    }

    @Test
    void appleDictionaryUsesANumericEncryptionKeyType() throws Exception {
        KerberosTgt packaged = AsRepPackager.pack(
                syntheticTgt(EncryptionHandler.random2Key(EncryptionType.AES256_CTS_HMAC_SHA1_96)),
                AsRepKeyMode.SESSION_KEY);

        Object value = packaged.toAppleDictionary().get("encryptionKeyType");
        assertEquals(Integer.class, value.getClass(),
                "encryptionKeyType must be a JSON number, unlike the string-valued expires_in beside it");
        assertNotNull(packaged.toAppleDictionary().getString("messageBuffer"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void ticketSurvivesConversionIntoTheJwePayload() throws Exception {
        KerberosTgt packaged = AsRepPackager.pack(
                syntheticTgt(EncryptionHandler.random2Key(EncryptionType.AES256_CTS_HMAC_SHA1_96)),
                AsRepKeyMode.SESSION_KEY);

        // Mirrors how PSSOResource assembles the login response before handing it to JweBuilder.
        org.json.JSONObject body = new org.json.JSONObject();
        body.put("token_type", "Bearer");
        body.put("login_tgt", packaged.toAppleDictionary());

        Map<String, Object> payload = JweBuilder.jsonObjectToMap(body);

        Object tgt = payload.get("login_tgt");
        assertInstanceOf(Map.class, tgt,
                "the nested ticket must become a Map, or it serialises into the JWE as an opaque object");

        Map<String, Object> tgtMap = (Map<String, Object>) tgt;
        assertEquals("krbtgt/" + REALM, tgtMap.get("serviceName"));
        assertEquals(EncryptionType.AES256_CTS_HMAC_SHA1_96.getValue(), tgtMap.get("encryptionKeyType"));
        assertNotNull(tgtMap.get("messageBuffer"));
        assertNotNull(tgtMap.get("sessionKey"));
    }

    /** Decodes the packaged AS-REP and decrypts enc-part using only what Apple's mapping exposes. */
    private static EncAsRepPart decryptEncPart(KerberosTgt packaged) throws Exception {
        AsRep decoded = KrbCodec.decode(packaged.asRep(), AsRep.class);
        assertEquals(REALM, decoded.getCrealm());

        EncryptionKey published = new EncryptionKey(packaged.encryptionKeyType(), packaged.sessionKey());
        byte[] plain = EncryptionHandler.decrypt(
                decoded.getEncryptedEncPart(), published, KeyUsage.AS_REP_ENCPART);

        return KrbCodec.decode(plain, EncAsRepPart.class);
    }

    /**
     * A TGT shaped like one from a real AS exchange. The ticket's own enc-part is opaque to us in
     * production, so it is filled with arbitrary bytes here.
     */
    private static TgtTicket syntheticTgt(EncryptionKey sessionKey) {
        PrincipalName tgsName = new PrincipalName("krbtgt/" + REALM);
        tgsName.setRealm(REALM);

        PrincipalName clientName = new PrincipalName(USER);
        clientName.setRealm(REALM);

        EncryptedData opaque = new EncryptedData();
        opaque.setEType(EncryptionType.AES256_CTS_HMAC_SHA1_96);
        opaque.setKvno(2);
        opaque.setCipher(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});

        Ticket ticket = new Ticket();
        ticket.setTktKvno(Ticket.TKT_KVNO);
        ticket.setRealm(REALM);
        ticket.setSname(tgsName);
        ticket.setEncryptedEncPart(opaque);

        EncAsRepPart encPart = new EncAsRepPart();
        encPart.setKey(sessionKey);
        encPart.setLastReq(new LastReq());
        encPart.setNonce(12345);
        encPart.setFlags(new TicketFlags());
        encPart.setAuthTime(new KerberosTime(END_TIME - 3600_000L));
        encPart.setEndTime(new KerberosTime(END_TIME));
        encPart.setSrealm(REALM);
        encPart.setSname(tgsName);

        return new TgtTicket(ticket, encPart, clientName);
    }
}
