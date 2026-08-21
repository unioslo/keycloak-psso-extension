package no.uio.keycloak.psso.token;

// The signed bytes are produced by tools/aliro/provision-card.sh: seven
// newline-separated lines, UTF-8, NO trailing newline.
//
//     aliro-issuance-v1
//     <chipId>        the cardSerial form param
//     <username>      NOT sent by the client -- see the note on binding below
//     <kid>           the userKeyId form param
//     <userKey>       the userKey form param, byte-for-byte as transmitted
//     <issuedAt>      ISO-8601 UTC, e.g. 2026-08-21T09:19:13Z
//     <generation>    decimal, 1 for a card's first key
//
// Binding: the username is deliberately not a form parameter. Reconstruct the
// statement with the username resolved from the *access token*, so a statement
// issued for one person cannot be replayed to register that card's key onto
// somebody else's account. If the check fails on a legitimate enrolment, the
// likely cause is preferred_username differing from the login name written into
// the card's credential id -- compare the two before changing anything here.

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class IssuanceStatement {

    public static final String VERSION = "aliro-issuance-v1";

    /** issuerKeyId -> trusted issuer public key. */
    private final Map<String, PublicKey> trusted = new LinkedHashMap<>();

    /**
     * @param caCertBundle one or more issuer certificates, concatenated PEM, held
     *                     in realm configuration as a single text value. A bundle
     *                     rather than one certificate because a single trusted
     *                     issuer cannot be rotated without a flag day: every card
     *                     issued under the old key stops enrolling the moment it
     *                     is replaced. Expect two entries during a rotation.
     *
     *                     Only the public keys are used -- nothing here builds or
     *                     validates a chain, because there is no chain: the card's
     *                     credential is a bare key, not a certificate. The
     *                     certificate is just a convenient envelope for a public
     *                     key that an admin can paste and read.
     */
    public IssuanceStatement(InputStream caCertBundle) throws Exception {
        Collection<? extends Certificate> certs = CertificateFactory
                .getInstance("X.509").generateCertificates(caCertBundle);
        if (certs.isEmpty()) throw new IllegalArgumentException("no issuer certificates configured");
        for (Certificate c : certs) {
            // The id is derived, never configured alongside the key: a hand-entered
            // id that drifts from its key fails as an unexplained bad signature.
            trusted.put(keyId(c.getPublicKey()), c.getPublicKey());
        }
    }

    /** Ids of every trusted issuer key -- log these at startup. */
    public Set<String> trustedKeyIds() {
        return trusted.keySet();
    }

    /**
     * base64(SHA-256(uncompressed point)) -- the same construction used for a
     * credential's kid, so there is one notion of "key id" in the system.
     */
    private static String keyId(PublicKey key) throws Exception {
        // The uncompressed point is the trailing 65 bytes of the SubjectPublicKeyInfo
        // for P-256; no ASN.1 parser needed for a curve we already fixed.
        byte[] spki = key.getEncoded();
        if (spki.length < 65) throw new IllegalArgumentException("not a P-256 public key");
        byte[] point = new byte[65];
        System.arraycopy(spki, spki.length - 65, point, 0, 65);
        return Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(point));
    }


    /**
     * @param username resolved from the access token, NOT from the request body.
     * @return true only if a trusted issuer signed exactly these facts.
     */
    public boolean verify(String signatureB64, String issuerKeyIdFromRequest,
                          String chipId, String username, String kid,
                          String userKey, String issuedAt, String generation)
            throws Exception {

        // Select by id rather than trying every key: an unknown issuer is then a
        // distinct, loggable condition instead of a puzzling verification failure.
        PublicKey issuerKey = trusted.get(issuerKeyIdFromRequest);
        if (issuerKey == null) return false;

        for (String f : new String[]{chipId, username, kid, userKey, issuedAt, generation}) {
            // A newline in any field would make two different fact sets share one
            // byte string. provision-card.sh rejects them at issuance; refuse them
            // here too rather than trusting that.
            if (f == null || f.indexOf('\n') >= 0 || f.isEmpty()) return false;
        }

        String statement = String.join("\n",
                VERSION, chipId, username, kid, userKey, issuedAt, generation);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(issuerKey);
        sig.update(statement.getBytes(StandardCharsets.UTF_8));
        try {
            return sig.verify(Base64.getDecoder().decode(signatureB64));
        } catch (Exception malformedSignature) {
            return false;
        }
    }

    /** Convenience for a bundle held in configuration as a string. */
    public static IssuanceStatement fromPem(String pemBundle) throws Exception {
        return new IssuanceStatement(
                new ByteArrayInputStream(pemBundle.getBytes(StandardCharsets.US_ASCII)));
    }
}


/*
 * Configuration. One textarea holding a concatenated PEM bundle, not a
 * repeatable single-line field -- PEM survives paste with its line breaks, and
 * generateCertificates() takes the whole thing in one call, so there is no
 * entry count to keep in step with reality:
 *
 *     new ProviderConfigProperty("cardEnrollIssuerCerts", "Card issuer certificates",
 *             "PEM bundle of the issuer keys allowed to vouch for card enrolments. "
 *             + "Two entries during a rotation; key ids are derived, not configured.",
 *             ProviderConfigProperty.TEXT_TYPE, null);
 *
 * Parse once when the configuration is read, not per request, and log
 * trustedKeyIds() at startup -- that one line turns "why is enrolment failing"
 * into a two-second comparison against the record's issuerKeyId.
 *
 * Wiring it into cardEnroll(), after the access token is validated and the user
 * is resolved, before any credential is touched:
 *
 *     if (!issuance.verify(issuerSignature, issuerKeyId, deviceUDID,
 *                          user.getUsername(), userKeyId, userKey,
 *                          issuedAt, generation)) {
 *         logger.warn("Rejected enrolment for " + user.getUsername()
 *                     + ": issuer statement did not verify (card " + deviceUDID + ")");
 *         return Response.status(Response.Status.FORBIDDEN).build();
 *     }
 *
 * Four new form params to add alongside the existing ones: issuedAt, generation,
 * issuerSignature, issuerKeyId.
 *
 * One unrelated thing worth fixing while in here: @FormParam only binds from an
 * application/x-www-form-urlencoded body, so with @Consumes(APPLICATION_JSON)
 * every parameter arrives null. enroll-card.py posts form-encoded; switch the
 * annotation to MediaType.APPLICATION_FORM_URLENCODED.
 */