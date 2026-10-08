package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.Krb5PrincipalName;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

/**
 * Mints the ephemeral PKINIT client certificate from a CA key held in realm config.
 *
 * This is the FreeIPA-shaped {@link CertificateSource}: the issuing CA is installed as a KDC
 * trust anchor there (ipa-cacert-manage install + ipa-certupdate) and scoped by a certmap rule,
 * so holding a small dedicated CA is acceptable. Never point this CA at Active Directory's
 * NTAuth store — AD cannot scope an NTAuth CA, which is why the AD path goes through an
 * enrollment agent instead.
 *
 * The certificate carries both identities a KDC might map on, so the same issuer output stays
 * AD-portable: the RFC 4556 id-pkinit-san (what MIT/FreeIPA match by default) and a Microsoft
 * UPN otherName. EKUs likewise cover id-pkinit-KPClientAuth, smartcardLogon and clientAuth.
 */
public final class LocalCaIssuer implements CertificateSource {

    private static final String ID_PKINIT_SAN = "1.3.6.1.5.2.2";
    private static final String ID_MS_UPN_SAN = "1.3.6.1.4.1.311.20.2.3";
    private static final String ID_PKINIT_KP_CLIENT_AUTH = "1.3.6.1.5.2.3.4";
    private static final String ID_MS_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2";

    /** Tolerates clock skew between Keycloak and the KDC, same bound Kerberos itself uses. */
    private static final long NOT_BEFORE_SKEW_SECONDS = 300;

    private final X509Certificate caCertificate;
    private final PrivateKey caKey;
    private final int lifetimeSeconds;
    private final SecureRandom random = new SecureRandom();

    public LocalCaIssuer(String caCertPem, String caKeyPem, int lifetimeSeconds) throws Exception {
        this.caCertificate = parseCertificate(caCertPem);
        this.caKey = parsePrivateKey(caKeyPem);
        this.lifetimeSeconds = lifetimeSeconds;
    }

    @Override
    public String name() {
        return "local-ca";
    }

    @Override
    public IssuedIdentity issueFor(String clientName, String realm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(caCertificate.getSubjectX500Principal().getEncoded()),
                new BigInteger(64, random).abs(),
                Date.from(now.minusSeconds(NOT_BEFORE_SKEW_SECONDS)),
                Date.from(now.plusSeconds(lifetimeSeconds)),
                new X500Name("CN=" + clientName + ",O=" + realm),
                keyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{
                KeyPurposeId.getInstance(new ASN1ObjectIdentifier(ID_PKINIT_KP_CLIENT_AUTH)),
                KeyPurposeId.getInstance(new ASN1ObjectIdentifier(ID_MS_SMARTCARD_LOGON)),
                KeyPurposeId.id_kp_clientAuth}));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                pkinitSan(clientName, realm),
                upnSan(clientName, realm)}));

        String signatureAlg = caKey.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlg).build(caKey);

        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
        return new IssuedIdentity(certificate, keyPair.getPrivate());
    }

    /** RFC 4556 §3.2.2: otherName of type id-pkinit-san carrying a KRB5PrincipalName. */
    static GeneralName pkinitSan(String clientName, String realm) throws Exception {
        Krb5PrincipalName krbName = new Krb5PrincipalName();
        krbName.setRealm(realm);
        krbName.setPrincipalName(new PrincipalName(clientName, NameType.NT_PRINCIPAL));

        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier(ID_PKINIT_SAN));
        otherName.add(new DERTaggedObject(true, 0, ASN1Primitive.fromByteArray(KrbCodec.encode(krbName))));
        return new GeneralName(GeneralName.otherName, new DERSequence(otherName));
    }

    /** Microsoft UPN otherName, so the same certificate maps in Active Directory later. */
    static GeneralName upnSan(String clientName, String realm) {
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier(ID_MS_UPN_SAN));
        otherName.add(new DERTaggedObject(true, 0, new DERUTF8String(clientName + "@" + realm)));
        return new GeneralName(GeneralName.otherName, new DERSequence(otherName));
    }

    static X509Certificate parseCertificate(String pem) throws Exception {
        try (var in = new java.io.ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    /** Accepts PKCS#8 ("PRIVATE KEY") and legacy PKCS#1/SEC1 ("RSA/EC PRIVATE KEY") PEM forms. */
    static PrivateKey parsePrivateKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object parsed = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (parsed instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (parsed instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo keyInfo) {
                return converter.getPrivateKey(keyInfo);
            }
            if (parsed instanceof PKCS8EncryptedPrivateKeyInfo) {
                throw new IllegalArgumentException("The CA key is password-protected; store it unencrypted "
                        + "in the Keycloak vault instead.");
            }
            throw new IllegalArgumentException("Unrecognised CA key PEM: "
                    + (parsed == null ? "empty" : parsed.getClass().getSimpleName()));
        }
    }
}
