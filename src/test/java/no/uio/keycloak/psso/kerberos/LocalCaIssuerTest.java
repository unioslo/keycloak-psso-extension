package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.Krb5PrincipalName;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalCaIssuerTest {

    private static final String REALM = "IPA.EXAMPLE.COM";

    private static TestCa ca;
    private static LocalCaIssuer issuer;
    private static CertificateSource.IssuedIdentity identity;

    @BeforeAll
    static void issueOnce() throws Exception {
        ca = new TestCa("CN=PSSO PKINIT Test CA,O=" + REALM);
        issuer = new LocalCaIssuer(ca.certificatePem(), ca.privateKeyPem(), 60);
        identity = issuer.issueFor("alice", REALM);
    }

    @Test
    void certificateIsSignedByTheCaAndCurrentlyValid() throws Exception {
        X509Certificate cert = identity.certificate();
        assertDoesNotThrow(() -> cert.verify(ca.keyPair.getPublic()));
        assertDoesNotThrow(() -> cert.checkValidity(new Date()));
        assertNotNull(identity.privateKey());
        assertEquals(cert.getPublicKey().getAlgorithm(), identity.privateKey().getAlgorithm());
    }

    @Test
    void carriesThePkinitSanTheKdcMapsOn() throws Exception {
        byte[] sanDer = findOtherName(identity.certificate(), "1.3.6.1.5.2.2");
        Krb5PrincipalName principal = KrbCodec.decode(sanDer, Krb5PrincipalName.class);

        assertEquals(REALM, principal.getRelm());
        assertEquals(List.of("alice"), principal.getPrincipalName().getNameStrings());
    }

    @Test
    void carriesTheMicrosoftUpnSanForActiveDirectoryLater() throws Exception {
        assertNotNull(findOtherName(identity.certificate(), "1.3.6.1.4.1.311.20.2.3"));
    }

    @Test
    void carriesThePkinitAndSmartcardLogonEkus() throws Exception {
        List<String> ekus = identity.certificate().getExtendedKeyUsage();
        assertTrue(ekus.contains("1.3.6.1.5.2.3.4"), "id-pkinit-KPClientAuth missing");
        assertTrue(ekus.contains("1.3.6.1.4.1.311.20.2.2"), "smartcardLogon missing (needed for AD)");
        assertTrue(ekus.contains("1.3.6.1.5.5.7.3.2"), "clientAuth missing");
    }

    @Test
    void lifetimeIsShortButBackdatedForClockSkew() {
        X509Certificate cert = identity.certificate();
        long lifeMillis = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
        assertEquals((300 + 60) * 1000L, lifeMillis);
        assertTrue(cert.getNotBefore().before(new Date()), "notBefore must be backdated");
    }

    /** Pulls the inner value of an otherName SAN with the given type OID. */
    private static byte[] findOtherName(X509Certificate cert, String oid) throws Exception {
        for (List<?> san : cert.getSubjectAlternativeNames()) {
            if ((Integer) san.get(0) != 0) {
                continue;
            }
            ASN1Sequence otherName = ASN1Sequence.getInstance((byte[]) san.get(1));
            if (oid.equals(ASN1ObjectIdentifier.getInstance(otherName.getObjectAt(0)).getId())) {
                return ASN1TaggedObject.getInstance(otherName.getObjectAt(1))
                        .getBaseObject().toASN1Primitive().getEncoded();
            }
        }
        throw new AssertionError("No otherName SAN with OID " + oid);
    }
}
