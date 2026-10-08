package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.CheckSumUtil;
import org.apache.kerby.kerberos.kerb.crypto.dh.DhGroup;
import org.apache.kerby.kerberos.kerb.crypto.dh.DiffieHellmanClient;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitCrypto;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.MethodData;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.AuthPack;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.DhRepInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDhKeyInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.Krb5PrincipalName;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsRep;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsReq;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PkAuthenticator;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.x509.type.AlgorithmIdentifier;
import org.apache.kerby.x509.type.DhParameter;
import org.apache.kerby.x509.type.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.jboss.logging.Logger;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The PKINIT (RFC 4556) AS exchange: a signed AuthPack instead of an encrypted timestamp, and a
 * Diffie-Hellman agreement instead of a password-derived reply key.
 *
 * Directory-portable by construction: MODP group 14 is the well-known group both MIT and Active
 * Directory accept (Kerby's own sample uses group 2, which modern KDCs reject via
 * pkinit_dh_min_bits=2048), and {@link #verifyKdcIdentity} accepts either the RFC 4556
 * id-pkinit-san that FreeIPA's KDC certificate carries or the dNSName that an AD domain
 * controller certificate carries. No RFC 8636 supportedKDFs are advertised, which pins the KDC
 * to the RFC 4556 octetstring2key KDF that Kerby's DiffieHellmanClient implements.
 *
 * Where the certificate comes from is {@link CertificateSource}'s problem, not this class's.
 */
public final class PkinitExchange {

    private static final Logger logger = Logger.getLogger(PkinitExchange.class);

    /** id-pkinit-authData: the eContentType of the signed AuthPack we send. */
    private static final ASN1ObjectIdentifier ID_PKINIT_AUTH_DATA =
            new ASN1ObjectIdentifier("1.3.6.1.5.2.3.1");
    /** id-pkinit-DHKeyData: the eContentType of the KDC's signed reply. */
    private static final ASN1ObjectIdentifier ID_PKINIT_DH_KEY_DATA =
            new ASN1ObjectIdentifier("1.3.6.1.5.2.3.2");
    private static final String ID_PKINIT_SAN = "1.3.6.1.5.2.2";
    /** dhpublicnumber (1.2.840.10046.2.1), spelled the way Kerby's OID factory expects. */
    private static final String DH_OID_CONTENT = "0x06 07 2A 86 48 ce 3e 02 01";

    private final KerberosRealmConfig config;
    private final AsExchange asExchange;
    private final SecureRandom random = new SecureRandom();

    public PkinitExchange(KerberosRealmConfig config) {
        this.config = config;
        this.asExchange = new AsExchange(config);
    }

    public TgtTicket requestTgt(String clientName, CertificateSource.IssuedIdentity identity,
                                KerberosRealmConfig.KdcAddress kdc)
            throws KrbException, IOException {

        Attempt attempt = buildAttempt(clientName, identity, null);
        KrbMessage reply = asExchange.send(attempt.asReq(), kdc);

        if (reply instanceof KrbError error) {
            // A KDC may answer the first PKINIT request with PREAUTH_REQUIRED purely to hand out
            // a PA-FX-COOKIE it wants echoed back. One rebuild (fresh nonce, time, checksum, DH
            // key) with the cookie attached; a second error is a real failure.
            if (error.getErrorCode() != KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED) {
                throw new KrbException(error.getErrorCode(), error.getEtext());
            }
            PaDataEntry cookie = extractCookie(error);
            logger.debugf("Platform SSO: KDC asked for another PKINIT round trip (cookie %s).",
                    cookie != null ? "present" : "absent");
            attempt = buildAttempt(clientName, identity, cookie);
            reply = asExchange.send(attempt.asReq(), kdc);
            if (reply instanceof KrbError secondError) {
                throw new KrbException(secondError.getErrorCode(), secondError.getEtext());
            }
        }

        return processReply((AsRep) reply, attempt, kdc);
    }

    private record Attempt(AsReq asReq, DiffieHellmanClient dhClient, int nonce, PrincipalName client) { }

    private Attempt buildAttempt(String clientName, CertificateSource.IssuedIdentity identity,
                                 PaDataEntry cookie) throws KrbException {
        String realm = config.realm();
        PrincipalName client = new PrincipalName(clientName, NameType.NT_PRINCIPAL);
        client.setRealm(realm);
        PrincipalName tgs = new PrincipalName("krbtgt/" + realm, NameType.NT_SRV_INST);
        tgs.setRealm(realm);

        int nonce = random.nextInt(Integer.MAX_VALUE);
        AsReq asReq = asExchange.buildAsReq(client, tgs, realm, nonce, null);

        // The paChecksum binds the signed AuthPack to this exact request body. RFC 4556 fixes
        // the algorithm to SHA-1; its strength is irrelevant because the whole structure is
        // inside our CMS signature.
        CheckSum checkSum = CheckSumUtil.makeCheckSum(CheckSumType.NIST_SHA,
                KrbCodec.encode(asReq.getReqBody()));

        DiffieHellmanClient dhClient = new DiffieHellmanClient();
        DHPublicKey dhPublicKey;
        try {
            dhPublicKey = dhClient.init(DhGroup.MODP_GROUP14);
        } catch (Exception e) {
            throw new KrbException("Failed to initialise the PKINIT Diffie-Hellman client", e);
        }

        AuthPack authPack = buildAuthPack(nonce, checkSum, dhPublicKey);

        PaPkAsReq paPkAsReq = new PaPkAsReq();
        paPkAsReq.setSignedAuthPack(signAuthPack(authPack, identity));

        PaData paData = new PaData();
        if (cookie != null) {
            paData.addElement(cookie);
        }
        paData.addElement(new PaDataEntry(PaDataType.PK_AS_REQ, KrbCodec.encode(paPkAsReq)));
        asReq.setPaData(paData);

        return new Attempt(asReq, dhClient, nonce, client);
    }

    private AuthPack buildAuthPack(int nonce, CheckSum checkSum, DHPublicKey dhPublicKey)
            throws KrbException {
        PkAuthenticator pkAuthenticator = new PkAuthenticator();
        long now = System.currentTimeMillis();
        pkAuthenticator.setCtime(new KerberosTime(now));
        pkAuthenticator.setCusec((int) ((now % 1000L) * 1000L));
        pkAuthenticator.setNonce(nonce);
        pkAuthenticator.setPaChecksum(checkSum.getChecksum());

        AlgorithmIdentifier dhAlgorithm = new AlgorithmIdentifier();
        dhAlgorithm.setAlgorithm(PkinitCrypto.createOid(DH_OID_CONTENT).getValue());
        DHParameterSpec params = dhPublicKey.getParams();
        DhParameter dhParameter = new DhParameter();
        dhParameter.setP(params.getP());
        dhParameter.setG(params.getG());
        dhParameter.setQ(params.getP().shiftRight(1));
        dhAlgorithm.setParameters(dhParameter);

        SubjectPublicKeyInfo publicValue = new SubjectPublicKeyInfo();
        publicValue.setAlgorithm(dhAlgorithm);
        publicValue.setSubjectPubKey(KrbCodec.encode(new Asn1Integer(dhPublicKey.getY())));

        AuthPack authPack = new AuthPack();
        authPack.setPkAuthenticator(pkAuthenticator);
        authPack.setClientPublicValue(publicValue);
        // Deliberately no supportedCMSTypes and no supportedKDFs: optional, and omitting the
        // KDFs pins the KDC to the RFC 4556 KDF.
        return authPack;
    }

    /**
     * Real CMS SignedData over the AuthPack, signed by the user certificate with the certificate
     * attached. Kerby's own client only produces an unsigned ContentInfo (anonymous PKINIT),
     * which FreeIPA and AD both reject for certificate clients — hence BouncyCastle here.
     */
    private byte[] signAuthPack(AuthPack authPack, CertificateSource.IssuedIdentity identity)
            throws KrbException {
        try {
            String signatureAlg = identity.privateKey().getAlgorithm().equals("EC")
                    ? "SHA256withECDSA" : "SHA256withRSA";
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlg)
                    .build(identity.privateKey());

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().build())
                    .build(signer, identity.certificate()));
            generator.addCertificate(new JcaX509CertificateHolder(identity.certificate()));

            CMSSignedData signed = generator.generate(
                    new CMSProcessableByteArray(ID_PKINIT_AUTH_DATA, KrbCodec.encode(authPack)),
                    true);
            return signed.getEncoded();
        } catch (KrbException e) {
            throw e;
        } catch (Exception e) {
            throw new KrbException("Failed to sign the PKINIT AuthPack", e);
        }
    }

    private TgtTicket processReply(AsRep asRep, Attempt attempt, KerberosRealmConfig.KdcAddress kdc)
            throws KrbException {
        PaDataEntry pkAsRepEntry = null;
        if (asRep.getPaData() != null) {
            for (PaDataEntry entry : asRep.getPaData().getElements()) {
                if (entry.getPaDataType() == PaDataType.PK_AS_REP) {
                    pkAsRepEntry = entry;
                    break;
                }
            }
        }
        if (pkAsRepEntry == null) {
            throw new KrbException("KDC accepted the request but returned no PA-PK-AS-REP");
        }

        PaPkAsRep paPkAsRep = KrbCodec.decode(pkAsRepEntry.getPaDataValue(), PaPkAsRep.class);
        DhRepInfo dhRepInfo = paPkAsRep.getDHRepInfo();
        if (dhRepInfo == null) {
            throw new KrbException("KDC chose the RSA (encKeyPack) PKINIT mode, which is not "
                    + "supported; configure the KDC for Diffie-Hellman key agreement");
        }
        if (dhRepInfo.getKdfId() != null) {
            // Should be impossible per RFC 8636 since we offered no KDFs; if the KDC does it
            // anyway, the enc-part decrypt below will fail and this log line explains why.
            logger.warnf("Platform SSO: KDC selected KDF %s despite none being offered; "
                    + "proceeding with the RFC 4556 KDF.", dhRepInfo.getKdfId());
        }

        byte[] kdcDhKeyInfoDer = verifySignedReply(dhRepInfo.getDHSignedData(), kdc);

        KdcDhKeyInfo kdcDhKeyInfo = KrbCodec.decode(kdcDhKeyInfoDer, KdcDhKeyInfo.class);
        BigInteger kdcPublicValue = KrbCodec.decode(
                kdcDhKeyInfo.getSubjectPublicKey().getValue(), Asn1Integer.class).getValue();

        DiffieHellmanClient dhClient = attempt.dhClient();
        EncryptionType etype = asRep.getEncryptedEncPart().getEType();
        EncryptionKey replyKey;
        try {
            DHPublicKey kdcPublicKey = PkinitCrypto.createDHPublicKey(
                    dhClient.getDhParam().getP(), dhClient.getDhParam().getG(), kdcPublicValue);
            dhClient.doPhase(kdcPublicKey.getEncoded());
            replyKey = dhClient.generateKey(null, null, etype);
        } catch (Exception e) {
            throw new KrbException("PKINIT Diffie-Hellman agreement failed", e);
        }

        logger.debugf("Platform SSO: PKINIT reply key agreed (%s) with %s:%d.",
                etype, kdc.host(), kdc.port());

        return asExchange.toTgtTicket(asRep, attempt.client(), replyKey, attempt.nonce());
    }

    /**
     * Verifies the KDC's SignedData — signature, eContentType, chain to the configured anchors,
     * and KDC identity — and returns the encapsulated KDCDHKeyInfo bytes.
     */
    byte[] verifySignedReply(byte[] dhSignedData, KerberosRealmConfig.KdcAddress kdc)
            throws KrbException {
        try {
            CMSSignedData cms = new CMSSignedData(dhSignedData);

            if (!ID_PKINIT_DH_KEY_DATA.equals(cms.getSignedContent().getContentType())) {
                throw new KrbException("KDC reply eContentType is "
                        + cms.getSignedContent().getContentType() + ", expected id-pkinit-DHKeyData");
            }

            Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
            if (signers.isEmpty()) {
                throw new KrbException("KDC reply SignedData carries no signer");
            }
            SignerInformation signer = signers.iterator().next();

            Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
            if (matches.isEmpty()) {
                throw new KrbException("KDC reply does not include the signer certificate");
            }
            X509CertificateHolder signerHolder = matches.iterator().next();
            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerHolder))) {
                throw new KrbException("KDC reply signature verification failed");
            }

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            X509Certificate signerCert = converter.getCertificate(signerHolder);
            List<X509Certificate> cmsCerts = new ArrayList<>();
            for (Object holder : cms.getCertificates().getMatches(null)) {
                cmsCerts.add(converter.getCertificate((X509CertificateHolder) holder));
            }
            validateChain(signerCert, cmsCerts, parseAnchors(config.kdcAnchorsPem()));

            verifyKdcIdentity(signerHolder, config.realm(), kdc.host());

            return (byte[]) cms.getSignedContent().getContent();
        } catch (KrbException e) {
            throw e;
        } catch (Exception e) {
            throw new KrbException("Could not verify the KDC's PKINIT reply: " + e.getMessage(), e);
        }
    }

    private static void validateChain(X509Certificate signerCert, List<X509Certificate> pool,
                                      List<X509Certificate> anchors) throws Exception {
        if (anchors.isEmpty()) {
            throw new KrbException("kerberosKdcAnchors must hold the CA that issued the KDC's "
                    + "PKINIT certificate (on FreeIPA, the IPA CA)");
        }
        Set<TrustAnchor> trust = new HashSet<>();
        for (X509Certificate anchor : anchors) {
            trust.add(new TrustAnchor(anchor, null));
        }
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(signerCert);

        PKIXBuilderParameters params = new PKIXBuilderParameters(trust, target);
        params.setRevocationEnabled(false);
        params.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(pool)));
        CertPathBuilder.getInstance("PKIX").build(params);
    }

    /**
     * The KDC must prove it is the KDC, not merely hold a certificate from the right CA.
     * FreeIPA KDC certificates carry an id-pkinit-san naming krbtgt/REALM; AD domain controller
     * certificates usually carry only a dNSName. Either satisfies us, which keeps this check
     * directory-portable — the dNSName must then match the configured KDC host.
     */
    static void verifyKdcIdentity(X509CertificateHolder kdcCert, String realm, String kdcHost)
            throws Exception {
        GeneralNames sans = GeneralNames.fromExtensions(
                kdcCert.getExtensions(), Extension.subjectAlternativeName);
        if (sans == null) {
            throw new KrbException("KDC certificate has no subjectAltName; cannot confirm it "
                    + "belongs to the KDC");
        }

        List<String> seen = new ArrayList<>();
        for (GeneralName name : sans.getNames()) {
            if (name.getTagNo() == GeneralName.otherName) {
                ASN1Sequence otherName = ASN1Sequence.getInstance(name.getName());
                String oid = ASN1ObjectIdentifier.getInstance(otherName.getObjectAt(0)).getId();
                if (ID_PKINIT_SAN.equals(oid)) {
                    byte[] inner = ASN1TaggedObject.getInstance(otherName.getObjectAt(1))
                            .getBaseObject().toASN1Primitive().getEncoded();
                    Krb5PrincipalName principal = KrbCodec.decode(inner, Krb5PrincipalName.class);
                    String flat = String.join("/", principal.getPrincipalName().getNameStrings());
                    seen.add(flat + "@" + principal.getRelm());
                    if (("krbtgt/" + realm).equals(flat) && realm.equals(principal.getRelm())) {
                        return;
                    }
                } else {
                    seen.add("otherName:" + oid);
                }
            } else if (name.getTagNo() == GeneralName.dNSName) {
                String dns = DERIA5String.getInstance(name.getName()).getString();
                seen.add("dns:" + dns);
                if (dns.equalsIgnoreCase(kdcHost)) {
                    return;
                }
            }
        }
        throw new KrbException("KDC certificate names " + seen + ", none of which match "
                + "krbtgt/" + realm + " or host " + kdcHost);
    }

    private static PaDataEntry extractCookie(KrbError error) {
        try {
            MethodData methodData = KrbCodec.decode(error.getEdata(), MethodData.class);
            for (PaDataEntry entry : methodData.getElements()) {
                if (entry.getPaDataType() == PaDataType.FX_COOKIE) {
                    return entry;
                }
            }
        } catch (Exception e) {
            logger.debugf("Platform SSO: Could not decode METHOD-DATA while looking for a "
                    + "PA-FX-COOKIE (%s); retrying without one.", e.getMessage());
        }
        return null;
    }

    static List<X509Certificate> parseAnchors(String pemBundle) throws Exception {
        List<X509Certificate> anchors = new ArrayList<>();
        if (pemBundle == null || pemBundle.isBlank()) {
            return anchors;
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (var in = new ByteArrayInputStream(pemBundle.getBytes(StandardCharsets.US_ASCII))) {
            for (var cert : factory.generateCertificates(in)) {
                anchors.add((X509Certificate) cert);
            }
        }
        return anchors;
    }
}
