package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDhKeyInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the reply-verification half of PKINIT offline: a pretend KDC backed by {@link TestCa}
 * signs a KDCDHKeyInfo exactly the way FreeIPA's KDC does, and we verify signature, chain,
 * eContentType and KDC identity without a network.
 */
class PkinitExchangeTest {

    private static final String REALM = "IPA.EXAMPLE.COM";
    private static final String KDC_HOST = "kdc.example.com";

    private static TestCa ipaCa;
    private static KeyPair kdcKeys;
    private static X509Certificate kdcCertWithPkinitSan;

    @BeforeAll
    static void mintKdc() throws Exception {
        ipaCa = new TestCa("CN=Pretend IPA CA,O=" + REALM);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kdcKeys = kpg.generateKeyPair();
        kdcCertWithPkinitSan = ipaCa.issue("CN=" + KDC_HOST, kdcKeys.getPublic(),
                LocalCaIssuer.pkinitSan("krbtgt/" + REALM, REALM));
    }

    @Test
    void acceptsAndUnwrapsAProperlySignedKdcReply() throws Exception {
        byte[] reply = signedKdcReply("1.3.6.1.5.2.3.2", BigInteger.valueOf(42));

        byte[] content = exchange(ipaCa.certificatePem())
                .verifySignedReply(reply, new KerberosRealmConfig.KdcAddress(KDC_HOST, 88));

        KdcDhKeyInfo keyInfo = KrbCodec.decode(content, KdcDhKeyInfo.class);
        BigInteger y = KrbCodec.decode(keyInfo.getSubjectPublicKey().getValue(), Asn1Integer.class)
                .getValue();
        assertEquals(BigInteger.valueOf(42), y);
    }

    @Test
    void rejectsAReplyChainingToADifferentCa() throws Exception {
        byte[] reply = signedKdcReply("1.3.6.1.5.2.3.2", BigInteger.ONE);
        TestCa wrongCa = new TestCa("CN=Somebody Else,O=EVIL");

        KrbException e = assertThrows(KrbException.class, () -> exchange(wrongCa.certificatePem())
                .verifySignedReply(reply, new KerberosRealmConfig.KdcAddress(KDC_HOST, 88)));
        assertTrue(e.getMessage().contains("verify"), e.getMessage());
    }

    @Test
    void rejectsTheWrongEContentType() throws Exception {
        // Signed correctly, but as id-pkinit-authData instead of id-pkinit-DHKeyData.
        byte[] reply = signedKdcReply("1.3.6.1.5.2.3.1", BigInteger.ONE);

        KrbException e = assertThrows(KrbException.class, () -> exchange(ipaCa.certificatePem())
                .verifySignedReply(reply, new KerberosRealmConfig.KdcAddress(KDC_HOST, 88)));
        assertTrue(e.getMessage().contains("eContentType")
                        || e.getCause() != null && e.getCause().getMessage().contains("eContentType"),
                e.getMessage());
    }

    @Test
    void kdcIdentityAcceptsThePkinitSanFreeipaUses() throws Exception {
        assertDoesNotThrow(() -> PkinitExchange.verifyKdcIdentity(
                new JcaX509CertificateHolder(kdcCertWithPkinitSan), REALM, "unrelated.host"));
    }

    @Test
    void kdcIdentityAcceptsTheDnsNameActiveDirectoryUses() throws Exception {
        X509Certificate dnsOnly = ipaCa.issue("CN=dc01", kdcKeys.getPublic(),
                new GeneralName(GeneralName.dNSName, "dc01.ad.example.com"));

        assertDoesNotThrow(() -> PkinitExchange.verifyKdcIdentity(
                new JcaX509CertificateHolder(dnsOnly), REALM, "dc01.ad.example.com"));
        assertThrows(KrbException.class, () -> PkinitExchange.verifyKdcIdentity(
                new JcaX509CertificateHolder(dnsOnly), REALM, "other.host"));
    }

    @Test
    void kdcIdentityRejectsACertificateForTheWrongRealm() throws Exception {
        X509Certificate otherRealm = ipaCa.issue("CN=kdc", kdcKeys.getPublic(),
                LocalCaIssuer.pkinitSan("krbtgt/OTHER.REALM", "OTHER.REALM"));

        assertThrows(KrbException.class, () -> PkinitExchange.verifyKdcIdentity(
                new JcaX509CertificateHolder(otherRealm), REALM, "unrelated.host"));
    }

    /** CMS SignedData the way a DH-mode KDC produces it. */
    private static byte[] signedKdcReply(String eContentTypeOid, BigInteger publicValue)
            throws Exception {
        KdcDhKeyInfo keyInfo = new KdcDhKeyInfo();
        keyInfo.setSubjectPublicKey(KrbCodec.encode(new Asn1Integer(publicValue)));
        keyInfo.setNonce(0);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kdcKeys.getPrivate()),
                        kdcCertWithPkinitSan));
        generator.addCertificate(new JcaX509CertificateHolder(kdcCertWithPkinitSan));

        return generator.generate(new CMSProcessableByteArray(
                new ASN1ObjectIdentifier(eContentTypeOid), KrbCodec.encode(keyInfo)), true)
                .getEncoded();
    }

    private static PkinitExchange exchange(String anchorsPem) throws Exception {
        var ctor = KerberosRealmConfig.class.getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        KerberosRealmConfig config = (KerberosRealmConfig) ctor.newInstance(
                REALM,
                java.util.List.of(new KerberosRealmConfig.KdcAddress(KDC_HOST, 88)),
                "login_tgt", "", "",
                AsRepKeyMode.SESSION_KEY, false, 5000,
                "", "", anchorsPem, 60);
        return new PkinitExchange(config);
    }
}
