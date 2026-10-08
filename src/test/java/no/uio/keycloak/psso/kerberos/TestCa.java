package no.uio.keycloak.psso.kerberos;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/** A throwaway in-memory CA for exercising certificate issuance and verification paths. */
final class TestCa {

    final KeyPair keyPair;
    final X509Certificate certificate;

    TestCa(String subject) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();

        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(subject), BigInteger.ONE,
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)),
                new X500Name(subject), keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        certificate = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
    }

    /** Issues an end-entity certificate with the given SANs, e.g. a pretend KDC certificate. */
    X509Certificate issue(String subject, java.security.PublicKey publicKey, GeneralName... sans)
            throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                // From the DER bytes, not the RFC 2253 string: the string form reverses RDN
                // order and breaks issuer/subject chaining during PKIX path building.
                X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)),
                new X500Name(subject), publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if (sans.length > 0) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        }
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
    }

    String certificatePem() throws Exception {
        return pem("CERTIFICATE", certificate.getEncoded());
    }

    String privateKeyPem() {
        return pem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
    }

    static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
