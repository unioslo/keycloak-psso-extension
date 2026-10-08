package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2Entry;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.MethodData;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.PaEncTsEnc;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.jboss.logging.Logger;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * A hand-driven AS exchange over TCP.
 *
 * Kerby's own {@code KrbClient} cannot be used for the password flow: its {@code KrbHandler}
 * parses ETYPE-INFO2 but keeps only the etype and throws the salt away, so
 * {@code AsRequestWithPasswd} always derives the key with {@code PrincipalName.makeSalt()}. That
 * works only against KDCs using the default realm+principal salt. FreeIPA issues random per-
 * principal salts, and Active Directory salts on sAMAccountName rather than whatever principal
 * string we were given — both produce the wrong key from a correct password, surfacing as an
 * indistinguishable KDC_ERR_PREAUTH_FAILED.
 *
 * Driving the exchange here lets us use the salt the KDC actually advertises. It is also the
 * foundation PKINIT needs, where the pre-auth data is a signed AuthPack instead of a timestamp.
 */
public final class AsExchange {

    private static final Logger logger = Logger.getLogger(AsExchange.class);

    /** RFC 4120 KDCOptions: forwardable | proxiable | renewable. */
    private static final int KDC_OPTIONS = 0x40000000 | 0x10000000 | 0x00800000;

    private static final int MAX_RESPONSE_BYTES = 1 << 20;

    private final KerberosRealmConfig config;
    private final SecureRandom random = new SecureRandom();

    public AsExchange(KerberosRealmConfig config) {
        this.config = config;
    }

    /**
     * Performs AS-REQ / AS-REP with encrypted-timestamp pre-authentication against one KDC.
     *
     * @param clientPrincipal client name, without realm
     * @param password        cleartext password
     */
    public TgtTicket requestTgtWithPassword(String clientPrincipal, String password,
                                            KerberosRealmConfig.KdcAddress kdc)
            throws KrbException, IOException {

        String realm = config.realm();
        PrincipalName client = new PrincipalName(clientPrincipal, NameType.NT_PRINCIPAL);
        client.setRealm(realm);
        PrincipalName tgs = new PrincipalName("krbtgt/" + realm, NameType.NT_SRV_INST);
        tgs.setRealm(realm);

        // First pass: no pre-auth. The KDC answers PREAUTH_REQUIRED and, crucially, tells us
        // which etype to use and what salt it holds for this principal.
        int nonce = random.nextInt(Integer.MAX_VALUE);
        KrbMessage first = send(buildAsReq(client, tgs, realm, nonce, null), kdc);

        SaltedEtype saltedEtype;
        if (first instanceof KrbError error) {
            if (error.getErrorCode() != KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED) {
                throw new KrbException(error.getErrorCode(), error.getEtext());
            }
            saltedEtype = readEtypeInfo2(error, client);
        } else {
            // Pre-auth not required, so there is no ETYPE-INFO2 to learn from: the reply key is
            // the long-term key under the default salt, at whatever etype the KDC chose.
            AsRep asRep = (AsRep) first;
            EncryptionKey longTermKey = EncryptionHandler.string2Key(password,
                    PrincipalName.makeSalt(client), null, asRep.getEncryptedEncPart().getEType());
            return toTgtTicket(asRep, client, longTermKey, nonce);
        }

        // Second pass: PA-ENC-TIMESTAMP encrypted under the correctly salted key.
        EncryptionKey clientKey = EncryptionHandler.string2Key(
                password, saltedEtype.salt(), saltedEtype.s2kParams(), saltedEtype.etype());

        // The salt is deliberately not logged: it is an input to the password-derived key, and
        // keeping it out of logs removes one ingredient from an offline attack.
        logger.debugf("Platform SSO: Pre-authenticating %s@%s with etype %s.",
                clientPrincipal, realm, saltedEtype.etype());

        nonce = random.nextInt(Integer.MAX_VALUE);
        PaDataEntry timestamp = encryptedTimestamp(clientKey);
        KrbMessage second = send(buildAsReq(client, tgs, realm, nonce, timestamp), kdc);

        if (second instanceof KrbError preauthError) {
            throw new KrbException(preauthError.getErrorCode(), preauthError.getEtext());
        }
        return toTgtTicket((AsRep) second, client, clientKey, nonce);
    }

    TgtTicket toTgtTicket(AsRep asRep, PrincipalName client, EncryptionKey replyKey, int nonce)
            throws KrbException {
        byte[] plain = EncryptionHandler.decrypt(
                asRep.getEncryptedEncPart(), replyKey, KeyUsage.AS_REP_ENCPART);

        EncAsRepPart encPart = decodeEncAsRepPart(plain);

        // Guards against a replayed or mismatched reply being accepted.
        if (encPart.getNonce() != nonce) {
            throw new KrbException("AS-REP nonce mismatch; expected " + nonce
                    + " but got " + encPart.getNonce());
        }
        return new TgtTicket(asRep.getTicket(), encPart, client);
    }

    /** DER identifier octets for [APPLICATION 25] (EncASRepPart) and [APPLICATION 26] (EncTGSRepPart). */
    private static final int TAG_ENC_AS_REP_PART = 0x79;
    private static final int TAG_ENC_TGS_REP_PART = 0x7A;

    /**
     * Decodes a decrypted AS-REP enc-part, tolerating the EncTGSRepPart tag.
     *
     * RFC 4120 §5.4.2 notes that some implementations unconditionally tag the enc-part as
     * EncTGSRepPart ([APPLICATION 26]) regardless of whether the reply is an AS-REP or a TGS-REP,
     * and says implementers may relax the tag check. MIT krb5 does exactly this, so FreeIPA does
     * too. Both tags wrap an identical EncKDCRepPart, so re-tagging is a faithful conversion —
     * and it normalises what we later re-encode for macOS to the spec-correct AS-REP form.
     */
    static EncAsRepPart decodeEncAsRepPart(byte[] plain) throws KrbException {
        try {
            return KrbCodec.decode(plain, EncAsRepPart.class);
        } catch (Exception e) {
            if (plain.length == 0 || (plain[0] & 0xFF) != TAG_ENC_TGS_REP_PART) {
                throw new KrbException("Decrypted the AS-REP but could not decode EncASRepPart", e);
            }
            byte[] retagged = plain.clone();
            retagged[0] = (byte) TAG_ENC_AS_REP_PART;
            try {
                return KrbCodec.decode(retagged, EncAsRepPart.class);
            } catch (Exception retryFailure) {
                throw new KrbException("Decrypted the AS-REP but could not decode its enc-part "
                        + "as either EncASRepPart or EncTGSRepPart", retryFailure);
            }
        }
    }

    private record SaltedEtype(EncryptionType etype, String salt, byte[] s2kParams) { }

    /**
     * Picks the first ETYPE-INFO2 entry whose etype we can actually compute, rather than simply
     * the first offered: a KDC may list types Kerby has no handler for.
     */
    private SaltedEtype readEtypeInfo2(KrbError error, PrincipalName client) throws KrbException {
        MethodData methodData;
        try {
            methodData = KrbCodec.decode(error.getEdata(), MethodData.class);
        } catch (Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debugf("Platform SSO: Undecodable METHOD-DATA: %s", hex(error.getEdata()));
            }
            throw new KrbException("Could not decode METHOD-DATA from the KDC's "
                    + "PREAUTH_REQUIRED reply; enable DEBUG on this package for the raw bytes", e);
        }

        List<EncryptionType> offered = new ArrayList<>();

        for (PaDataEntry entry : methodData.getElements()) {
            if (entry.getPaDataType() != PaDataType.ETYPE_INFO2) {
                continue;
            }
            EtypeInfo2 info;
            try {
                info = KrbCodec.decode(entry.getPaDataValue(), EtypeInfo2.class);
            } catch (Exception e) {
                if (logger.isDebugEnabled()) {
                    logger.debugf("Platform SSO: Undecodable ETYPE-INFO2: %s", hex(entry.getPaDataValue()));
                }
                throw new KrbException("Could not decode ETYPE-INFO2 from the KDC", e);
            }
            for (EtypeInfo2Entry candidate : info.getElements()) {
                EncryptionType etype = candidate.getEtype();
                offered.add(etype);
                if (!EncryptionHandler.isImplemented(etype)) {
                    continue;
                }
                // An absent salt means the KDC uses the default; an empty one means literally
                // empty, so only substitute when it is missing.
                String salt = candidate.getSalt();
                if (salt == null) {
                    salt = PrincipalName.makeSalt(client);
                }
                return new SaltedEtype(etype, salt, candidate.getS2kParams());
            }
        }

        if (offered.isEmpty()) {
            throw new KrbException("KDC required pre-authentication but sent no ETYPE-INFO2");
        }
        throw new KrbException("KDC offered only unsupported encryption types: " + offered
                + ". Kerby implements AES-SHA1, RC4 and Camellia, but not the RFC 8009 "
                + "AES-SHA2 types (19/20).");
    }



    private PaDataEntry encryptedTimestamp(EncryptionKey clientKey) throws KrbException {
        PaEncTsEnc timestamp = new PaEncTsEnc();
        KerberosTime now = KerberosTime.now();
        timestamp.setPaTimestamp(now);
        timestamp.setPaUsec((int) ((now.getTime() % 1000L) * 1000L));

        EncryptedData encrypted = EncryptionHandler.encrypt(
                KrbCodec.encode(timestamp), clientKey, KeyUsage.AS_REQ_PA_ENC_TS);

        return new PaDataEntry(PaDataType.ENC_TIMESTAMP, KrbCodec.encode(encrypted));
    }

    AsReq buildAsReq(PrincipalName client, PrincipalName tgs, String realm,
                             int nonce, PaDataEntry preauth) {
        KdcReqBody body = new KdcReqBody();
        body.setKdcOptions(new KdcOptions(KDC_OPTIONS));
        body.setCname(client);
        body.setRealm(realm);
        body.setSname(tgs);
        // KerberosTime constants are already in milliseconds. The KDC clamps this to its own
        // policy maximum anyway.
        body.setTill(new KerberosTime(System.currentTimeMillis() + KerberosTime.DAY));
        body.setNonce(nonce);
        body.setEtypes(requestedEtypes());

        AsReq asReq = new AsReq();
        asReq.setReqBody(body);
        if (preauth != null) {
            PaData paData = new PaData();
            paData.addElement(preauth);
            asReq.setPaData(paData);
        }
        return asReq;
    }

    /** Only advertise what we can actually derive a key for. */
    static List<EncryptionType> requestedEtypes() {
        List<EncryptionType> etypes = new ArrayList<>();
        for (EncryptionType candidate : new EncryptionType[]{
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                EncryptionType.AES128_CTS_HMAC_SHA1_96,
                EncryptionType.CAMELLIA256_CTS_CMAC,
                EncryptionType.ARCFOUR_HMAC}) {
            if (EncryptionHandler.isImplemented(candidate)) {
                etypes.add(candidate);
            }
        }
        return etypes;
    }

    /**
     * Kerberos over TCP: each message is prefixed with its length as a 4-byte big-endian value.
     */
    KrbMessage send(AsReq request, KerberosRealmConfig.KdcAddress kdc)
            throws KrbException, IOException {
        byte[] encoded = KrbCodec.encode(request);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(kdc.host(), kdc.port()), config.timeoutMs());
            socket.setSoTimeout(config.timeoutMs());

            OutputStream out = socket.getOutputStream();
            out.write(ByteBuffer.allocate(4).putInt(encoded.length).array());
            out.write(encoded);
            out.flush();

            DataInputStream in = new DataInputStream(socket.getInputStream());
            int length = in.readInt();
            if (length <= 0 || length > MAX_RESPONSE_BYTES) {
                throw new KrbException("KDC returned an implausible message length: " + length);
            }
            byte[] response = new byte[length];
            in.readFully(response);

            try {
                return KrbCodec.decodeMessage(ByteBuffer.wrap(response));
            } catch (Exception e) {
                if (logger.isDebugEnabled()) {
                    logger.debugf("Platform SSO: Undecodable KDC response (%d bytes): %s",
                            response.length, hex(response));
                }
                throw new KrbException("Could not decode the " + response.length
                        + "-byte KDC response; enable DEBUG on this package for the raw bytes", e);
            }
        }
    }

    /** Hex for diagnosing protocol-level failures against an unfamiliar KDC. */
    private static String hex(byte[] bytes) {
        if (bytes == null) {
            return "<null>";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
