package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.jboss.logging.Logger;

/**
 * Turns a TGT obtained from a KDC into the AS-REP shape macOS imports.
 *
 * The ticket itself is opaque and passes through untouched; only the enc-part is re-encrypted,
 * under a key we then publish alongside it. See {@link AsRepKeyMode} for why.
 */
public final class AsRepPackager {

    private static final Logger logger = Logger.getLogger(AsRepPackager.class);

    private AsRepPackager() {
    }

    public static KerberosTgt pack(TgtTicket tgt, AsRepKeyMode mode) throws KrbException {
        EncKdcRepPart encPart = tgt.getEncKdcRepPart();
        EncryptionKey sessionKey = encPart.getKey();

        EncryptionKey replyKey = switch (mode) {
            case SESSION_KEY -> sessionKey;
            case RANDOM_REPLY_KEY -> EncryptionHandler.random2Key(sessionKey.getKeyType());
        };

        // Clear the nonce before handing the ticket to macOS.
        //
        // The nonce exists to bind an AS-REP to the AS-REQ that asked for it, and AsExchange has
        // already verified it against the request we sent. macOS then imports the ticket through
        // krb5_init_creds_step on a context that never generated an AS-REQ, so Heimdal compares
        // our nonce against its own uninitialised 0 and rejects a mismatch with
        // KRB5KRB_AP_ERR_MODIFIED. Apple cannot know the value we used with the KDC, so keeping
        // it can never help — observed as an import failure against FreeIPA.
        encPart.setNonce(0);

        // Re-encode the enc-part. It is an EncAsRepPart instance, so this keeps application
        // tag 25 rather than the TGS-REP tag.
        byte[] plainEncPart = KrbCodec.encode(encPart);
        EncryptedData encrypted = EncryptionHandler.encrypt(plainEncPart, replyKey, KeyUsage.AS_REP_ENCPART);

        PrincipalName client = tgt.getClientPrincipal();

        // A client principal parsed without a realm would otherwise encode a null crealm. For a
        // TGT the client and service realms coincide, so the enc-part is a safe fallback.
        String clientRealm = client.getRealm();
        if (clientRealm == null || clientRealm.isEmpty()) {
            clientRealm = encPart.getSrealm();
        }

        AsRep asRep = new AsRep();
        asRep.setCname(client);
        asRep.setCrealm(clientRealm);
        asRep.setTicket(tgt.getTicket());
        asRep.setEncryptedEncPart(encrypted);

        byte[] asRepDer = KrbCodec.encode(asRep);

        KerberosTgt packaged = new KerberosTgt(
                flatName(client),
                encPart.getSrealm(),
                flatName(encPart.getSname()),
                replyKey.getKeyType().getValue(),
                replyKey.getKeyData(),
                asRepDer,
                encPart.getEndTime() == null ? 0L : encPart.getEndTime().getTime());

        logger.debugf("Platform SSO: Packaged TGT for %s (%s), etype %d, %d byte AS-REP.",
                packaged.clientName(), packaged.serviceName(),
                packaged.encryptionKeyType(), asRepDer.length);

        return packaged;
    }

    /**
     * Joins the name components with "/" but leaves the realm off, matching Apple's documented
     * examples ("foo", "krbtgt/EXAMPLE.COM"). {@code PrincipalName.getName()} would append
     * "@REALM".
     */
    private static String flatName(PrincipalName principal) {
        if (principal == null || principal.getNameStrings() == null) {
            return null;
        }
        return String.join("/", principal.getNameStrings());
    }
}
