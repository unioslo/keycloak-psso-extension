package no.uio.keycloak.psso.token;

// Everything /psso/cardenroll should check before it stores a credential, behind
// one call. Companion to IssuanceStatement, which holds the trust list and does
// the signature; this adds the policy around it.
//
//     Result r = validator.validate(user.getUsername(), deviceUDID, userKey,
//                                   userKeyId, issuedAt, generation,
//                                   issuerSignature, issuerKeyId);
//     if (!r.ok) {
//         logger.warn("Rejected enrolment for " + user.getUsername() + ": " + r.reason);
//         return Response.status(Response.Status.FORBIDDEN).build();
//     }
//     // r.key / r.point are the validated key, ready to store
//
// Order is deliberate: the issuer signature is checked FIRST, before anything
// else is parsed. The statement covers the userKey verbatim, so once it verifies
// every field below is issuer-signed rather than attacker-supplied -- which is
// what makes it safe to hand the key material to a parser at all. Nothing here
// checks the userKey "against" the PEM: there is no direct relationship between
// them. The PEM verifies the statement; the statement carries the key.
//
// What this cannot tell you: whether the private half is on a card, or whether
// that card is present. The issuer vouches for provenance, not possession. Proof
// of possession needs a signature from the card over the enrolment nonce.

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;

public final class CardEnrollmentValidator {

    // P-256. Fixed because the applet has one curve and always will -- the key
    // pair is generated on-card by AliroApplet against secp256r1.
    private static final BigInteger P = new BigInteger(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger B = new BigInteger(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    private static final Pattern HEX_POINT = Pattern.compile("04[0-9A-Fa-f]{128}");

    private static String str(Object o) { return o == null ? null : o.toString(); }

    /** Outcome, with a specific reason so the log says what actually failed. */
    public static final class Result {
        public final boolean ok;
        public final String reason;
        public final ECPublicKey key;
        /** Uncompressed point as uppercase hex, the canonical form for logging. */
        public final String point;

        private Result(boolean ok, String reason, ECPublicKey key, String point) {
            this.ok = ok; this.reason = reason; this.key = key; this.point = point;
        }
        static Result no(String reason) { return new Result(false, reason, null, null); }
        static Result yes(ECPublicKey k, String point) { return new Result(true, null, k, point); }
    }

    private final IssuanceStatement issuers;
    private final Set<String> allowedSerialPrefixes;
    private final long maxStatementAge;   // seconds; 0 disables the check

    /**
     * @param issuerCertBundle      concatenated PEM of every issuer allowed to vouch
     * @param allowedSerialPrefixes e.g. Set.of("CPLC:") in production. provision-card.sh
     *                              falls back to a "SIM:" identity when a chip reports a
     *                              blank CPLC, and a simulator card must never be
     *                              enrollable against a real account. Empty set = allow all.
     * @param maxStatementAge       reject records older than this. Signatures do not
     *                              expire on their own, so without a bound a record for a
     *                              card decommissioned two years ago stays enrollable.
     */
    public CardEnrollmentValidator(String issuerCertBundle,
                                  Set<String> allowedSerialPrefixes,
                                  java.time.Duration maxStatementAge) throws Exception {
        this.issuers = new IssuanceStatement(
                new ByteArrayInputStream(issuerCertBundle.getBytes(StandardCharsets.US_ASCII)));
        this.allowedSerialPrefixes = allowedSerialPrefixes;
        this.maxStatementAge = maxStatementAge == null ? 0 : maxStatementAge.getSeconds();
    }

    /** Trusted issuer key ids -- log at startup, compare against a record's issuerKeyId. */
    public Set<String> trustedIssuers() {
        return issuers.trustedKeyIds();
    }

    // -----------------------------------------------------------------------
    // Configuration
    //
    // Read from the "Platform Single Sign-on" component config, i.e. the same
    // realm-settings tab as the registration token and the OIDC client:
    //
    //   caKeysForCardValidation  concatenated PEM, one block per trusted issuer.
    //                            A bundle rather than a single certificate so an
    //                            issuer key can be rotated without a flag day.
    //   cardSerialPrefixes       comma-separated, e.g. "CPLC:". Empty accepts any
    //                            card, which is right for bring-up and wrong for
    //                            production: provision-card.sh falls back to a
    //                            "SIM:" identity when a chip reports blank CPLC.
    //   cardEnrollMaxAgeDays     default 30.

    public static final String CONFIG_ISSUER_CERTS = "caKeysForCardValidation";
    public static final String CONFIG_SERIAL_PREFIXES = "cardSerialPrefixes";
    public static final String CONFIG_MAX_AGE_DAYS = "cardEnrollMaxAgeDays";

    private record Cached(String configKey, CardEnrollmentValidator validator) {}

    private static final Logger logger = Logger.getLogger(CardEnrollmentValidator.class);
    private static final Map<String, Cached> CACHE = new ConcurrentHashMap<>();

    /**
     * The validator for a realm's PSSO configuration, reused until that
     * configuration changes.
     *
     * Parsing a PEM bundle on every enrollment would be wasteful, but the cache key
     * has to cover EVERY setting that goes into the object: keyed on the
     * certificates alone, editing the serial prefixes or the age bound would leave
     * the old policy in force until the next restart -- and silently, which is the
     * worst way for an allowlist to fail. Keyed by component id so a multi-realm
     * deployment does not thrash a single slot.
     *
     * @param pssoConfig the "Platform Single Sign-on" ComponentModel the caller
     *                   already resolved; never null.
     * @throws IllegalStateException if no issuer certificates are configured, so the
     *         caller can answer 503 rather than quietly accepting everything.
     */
    public static CardEnrollmentValidator forConfig(ComponentModel pssoConfig) throws Exception {
        String pem = pssoConfig.get(CONFIG_ISSUER_CERTS);
        if (pem == null || pem.isBlank()) {
            throw new IllegalStateException(
                    CONFIG_ISSUER_CERTS + " is not set: card enrollment is unconfigured");
        }
        String prefixes = Optional.ofNullable(pssoConfig.get(CONFIG_SERIAL_PREFIXES)).orElse("");
        String maxAgeDays = Optional.ofNullable(pssoConfig.get(CONFIG_MAX_AGE_DAYS)).orElse("30");
        if (maxAgeDays.isBlank()) maxAgeDays = "30";
        String configKey = String.join("\n", pem, prefixes, maxAgeDays);

        Cached cached = CACHE.get(pssoConfig.getId());
        if (cached != null && cached.configKey().equals(configKey)) {
            return cached.validator();
        }

        long days;
        try {
            days = Long.parseLong(maxAgeDays.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(CONFIG_MAX_AGE_DAYS + " is not a number: " + maxAgeDays);
        }

        CardEnrollmentValidator v = new CardEnrollmentValidator(
                pem,
                prefixes.isBlank() ? Set.of() : Set.of(prefixes.split("\\s*,\\s*")),
                java.time.Duration.ofDays(days));
        CACHE.put(pssoConfig.getId(), new Cached(configKey, v));
        logger.info("PlatformSSO: Card enrollment configured"
                + ": trusted issuers " + v.trustedIssuers()
                + ", serial prefixes " + (prefixes.isBlank() ? "(any)" : prefixes)
                + ", max record age " + days + "d");
        return v;
    }

    public Result validate(String username, String cardSerial, String userKey,
                           String userKeyId, String issuedAt, String generation,
                           String issuerSignature, String issuerKeyId) {
        return validate(username, cardSerial, userKey, userKeyId, issuedAt, generation,
                issuerSignature, issuerKeyId, Instant.now());
    }

    /** @param now injectable so the age bound can be tested. */
    public Result validate(String username, String cardSerial, String userKey,
                           String userKeyId, String issuedAt, String generation,
                           String issuerSignature, String issuerKeyId, Instant now) {

        for (String f : List.of(nz(username), nz(cardSerial), nz(userKey), nz(userKeyId),
                nz(issuedAt), nz(generation), nz(issuerSignature), nz(issuerKeyId))) {
            if (f.isEmpty()) return Result.no("missing required parameter");
        }

        // 1. Provenance, before anything else is looked at. Every field below is
        //    covered by this signature, so passing it is what makes them trustworthy.
        try {
            if (!issuers.verify(issuerSignature, issuerKeyId, cardSerial, username,
                    userKeyId, userKey, issuedAt, generation)) {
                return Result.no(issuers.trustedKeyIds().contains(issuerKeyId)
                        ? "issuer statement did not verify"
                        : "unknown issuer key id " + issuerKeyId
                        + " (trusted: " + issuers.trustedKeyIds() + ")");
            }
        } catch (Exception e) {
            return Result.no("issuer statement could not be checked: " + e);
        }

        // 2. Freshness of the issuance itself, distinct from the token's auth_time.
        Instant issued;
        try {
            issued = Instant.parse(issuedAt);
        } catch (DateTimeParseException e) {
            return Result.no("issuedAt is not ISO-8601: " + issuedAt);
        }
        if (issued.isAfter(now.plusSeconds(300))) {
            return Result.no("issuedAt is in the future: " + issuedAt);
        }
        if (maxStatementAge > 0 && issued.plusSeconds(maxStatementAge).isBefore(now)) {
            return Result.no("issuance record is older than the accepted window: " + issuedAt);
        }

        // 3. Which cards this deployment will accept at all.
        if (!allowedSerialPrefixes.isEmpty()
                && allowedSerialPrefixes.stream().noneMatch(cardSerial::startsWith)) {
            return Result.no("card serial " + cardSerial + " has no accepted prefix "
                    + allowedSerialPrefixes);
        }

        try {
            if (Integer.parseInt(generation) < 1) return Result.no("generation must be >= 1");
        } catch (NumberFormatException e) {
            return Result.no("generation is not a number: " + generation);
        }

        // 4. The key itself. Signed data by this point, but still parsed defensively:
        //    a malformed key that gets stored fails later at login, somewhere far less
        //    informative than here.
        byte[] point;
        try {
            point = uncompressedPoint(userKey);
        } catch (Exception e) {
            return Result.no("userKey is not a usable P-256 public key: " + e.getMessage());
        }

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 33, 65));
        if (x.signum() == 0 && y.signum() == 0) return Result.no("userKey is the point at infinity");
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) return Result.no("userKey coordinate >= p");
        // y^2 == x^3 - 3x + b (mod p). An off-curve key is not a key; storing one
        // guarantees a confusing signature failure at first tap instead of here.
        if (!y.modPow(BigInteger.TWO, P).equals(
                x.multiply(x).multiply(x).subtract(THREE.multiply(x)).add(B).mod(P))) {
            return Result.no("userKey is not a point on P-256");
        }

        // 5. The kid must be what the rest of the system will compute from the key:
        //    base64(SHA-256(04||X||Y)). PSSO puts this in the assertion header, so a
        //    mismatch means the stored credential can never be found at login.
        String derived;
        try {
            derived = Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(point));
        } catch (Exception e) {
            return Result.no("cannot hash the key: " + e);
        }
        if (!derived.
                equals(userKeyId)) {
            return Result.no("userKeyId does not match the key (expected " + derived + ")");
        }

        try {
            return Result.yes(toPublicKey(x, y), HexFormat.of().formatHex(point).toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            return Result.no("cannot build a public key: " + e);
        }
    }

    private static String nz(String s) { return s == null ? "" : s.trim(); }

    /**
     * Accepts every shape provision-card.sh can emit (--key-format jwk|hex|spki) and
     * normalises to 04||X||Y. Auto-detected rather than configured: the value is
     * already issuer-signed, so there is no attacker-chosen format to be steered by,
     * and one less setting to keep in step with the issuing side.
     */
    static byte[] uncompressedPoint(String userKey) {
        String s = userKey.trim();

        if (s.startsWith("{")) {
            // Keycloak's own parser rather than a regex over the JSON: member order,
            // whitespace and unexpected members are then somebody else's problem.
            // Deliberately NOT JWKParser.toPublicKey() -- that needs CryptoIntegration
            // initialised, which is true inside the server but makes this untestable
            // anywhere else, and it hands back a PublicKey when what the kid check
            // needs is the point bytes.
            JWK jwk = JWKParser.create().parse(s).getJwk();
            if (!"EC".equals(jwk.getKeyType())) {
                throw new IllegalArgumentException("kty is " + jwk.getKeyType() + ", not EC");
            }
            // 26.5.2 deserialises to a plain JWK with crv/x/y in otherClaims; read the
            // typed subclass too so an upgrade that starts returning ECPublicJWK does
            // not quietly turn every coordinate into a null.
            String crv, xs, ys;
            if (jwk instanceof ECPublicJWK ec) {
                crv = ec.getCrv(); xs = ec.getX(); ys = ec.getY();
            } else {
                Map<String, Object> c = jwk.getOtherClaims();
                crv = str(c.get("crv")); xs = str(c.get("x")); ys = str(c.get("y"));
            }
            if (crv != null && !"P-256".equals(crv)) {
                throw new IllegalArgumentException("curve is " + crv + ", not P-256");
            }
            if (xs == null || ys == null) throw new IllegalArgumentException("JWK has no x/y");
            byte[] x = Base64.getUrlDecoder().decode(xs);
            byte[] y = Base64.getUrlDecoder().decode(ys);
            if (x.length != 32 || y.length != 32) {
                throw new IllegalArgumentException("JWK coordinates are not 32 bytes");
            }
            byte[] p = new byte[65];
            p[0] = 0x04;
            System.arraycopy(x, 0, p, 1, 32);
            System.arraycopy(y, 0, p, 33, 32);
            return p;
        }

        if (HEX_POINT.matcher(s).matches()) {
            return HexFormat.of().parseHex(s);
        }

        // SubjectPublicKeyInfo, base64. For P-256 the point is the trailing 65 bytes.
        byte[] der = Base64.getDecoder().decode(s);
        if (der.length < 65) throw new IllegalArgumentException("SPKI too short");
        byte[] p = Arrays.copyOfRange(der, der.length - 65, der.length);
        if (p[0] != 0x04) throw new IllegalArgumentException("SPKI does not end in an uncompressed point");
        return p;
    }

    private static ECPublicKey toPublicKey(BigInteger x, BigInteger y) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        return (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
    }
}