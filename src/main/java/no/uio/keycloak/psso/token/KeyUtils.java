package no.uio.keycloak.psso.token;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.List;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.jboss.logging.Logger;

public  class KeyUtils {
    private static final Logger logger = Logger.getLogger(KeyUtils.class);

    // Try to parse a Base64 string that may be either:
    // - raw X9.63 uncompressed public key: 0x04||X||Y (65 bytes for P-256)
    // - SubjectPublicKeyInfo (X.509/DER) (typical output of many libs)
    // Returns the Java ECPublicKey and the Nimbus ECKey public JWK.
    public static ECPublicKey parseEcPublicKeyFromBase64(String b64) throws Exception {
        byte[] raw = Base64.getDecoder().decode(b64);

        // If looks like X9.63 uncompressed (first byte 0x04 and length 65)
        if (raw.length == 65 && raw[0] == 0x04) {
            byte[] xb = new byte[32];
            byte[] yb = new byte[32];
            System.arraycopy(raw, 1, xb, 0, 32);
            System.arraycopy(raw, 1 + 32, yb, 0, 32);
            logger.info("Detected X9.63 uncompressed public key (65 bytes).");

            return buildEcPublicKeyFromXY(xb, yb);
        }

        // Otherwise assume it's ASN.1 SubjectPublicKeyInfo (X.509)
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec ks = new X509EncodedKeySpec(raw);
            PublicKey pk = kf.generatePublic(ks);
            if (pk instanceof ECPublicKey) {
                logger.info("Detected X.509/SPKI public key (DER).");
                return (ECPublicKey) pk;
            } else {
                throw new IllegalArgumentException("Parsed public key is not EC");
            }
        } catch (Exception e) {
            // fallback: try to find the X9.63 portion inside an SPKI blob (heuristic)
            logger.warn("Failed to parse as X.509/SPKI: " + e.getMessage() + " — trying to find X9.63 inside the blob...");
            // naive search for 0x04 followed by 64 bytes
            for (int i = 0; i < raw.length - 65; i++) {
                if (raw[i] == 0x04 && (i + 65) <= raw.length) {
                    boolean plausible = true;
                    // quick plausibility check: not necessary but keeps it safe
                    if (plausible) {
                        byte[] x963 = new byte[65];
                        System.arraycopy(raw, i, x963, 0, 65);
                        byte[] xb = new byte[32];
                        byte[] yb = new byte[32];
                        System.arraycopy(x963, 1, xb, 0, 32);
                        System.arraycopy(x963, 1 + 32, yb, 0, 32);
                        return buildEcPublicKeyFromXY(xb, yb);
                    }
                }
            }
            throw new IllegalArgumentException("Unrecognized EC public key format");
        }
    }

    // Build Java EC public key from raw X (32) and Y (32) bytes for secp256r1
    public static ECPublicKey buildEcPublicKeyFromXY(byte[] xb, byte[] yb) throws Exception {
        BigInteger x = new BigInteger(1, xb);
        BigInteger y = new BigInteger(1, yb);
        // Get standard P-256 params from ECGenParameterSpec
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPoint w = new ECPoint(x, y);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey pk = kf.generatePublic(pubSpec);
        return (ECPublicKey) pk;
    }

    // Convert Java ECPublicKey to Nimbus ECKey (public JWK)
    public static ECKey toNimbusEcJwk(ECPublicKey pub, String kid) {
        return new ECKey.Builder(Curve.P_256, pub)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
                .keyID(kid)
                .build();
    }

    // Utility logger for X/Y in different encodings
    public static void logPublicKeyFormats(ECPublicKey pub, String label) {
        ECPoint w = pub.getW();
        byte[] xb = unsignedToFixedLength(w.getAffineX().toByteArray(), 32);
        byte[] yb = unsignedToFixedLength(w.getAffineY().toByteArray(), 32);

        logger.info(label + " X (hex) : " + bytesToHex(xb));
        logger.info(label + " Y (hex) : " + bytesToHex(yb));
        logger.info(label + " X (b64u): " + Base64URL.encode(xb).toString());
        logger.info(label + " Y (b64u): " + Base64URL.encode(yb).toString());

        // x9.63
        byte[] x963 = new byte[1 + xb.length + yb.length];
        x963[0] = 0x04;
        System.arraycopy(xb, 0, x963, 1, xb.length);
        System.arraycopy(yb, 0, x963, 1 + xb.length, yb.length);
        logger.info(label + " X9.63 (b64u): " + Base64URL.encode(x963).toString());
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    public static byte[] unsignedToFixedLength(byte[] src, int fixedLen) {
        if (src.length == fixedLen) return src;
        if (src.length > fixedLen) {
            return Arrays.copyOfRange(src, src.length - fixedLen, src.length);
        } else {
            byte[] out = new byte[fixedLen];
            System.arraycopy(src, 0, out, fixedLen - src.length, src.length);
            return out;
        }
    }

    // Call this when you detect a 32-byte device key
    public static List<ECPublicKey> expandXToCandidates(byte[] xBytes) throws Exception {
        List<ECPublicKey> candidates = new ArrayList<>();
        // P-256 params
        BigInteger p = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        BigInteger a = new BigInteger("-3"); // -3 mod p
        BigInteger b = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

        BigInteger x = new BigInteger(1, xBytes);

        // y^2 = x^3 + a*x + b (mod p)
        BigInteger rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);

        // modular sqrt(s) -> get y (two roots y and p-y)
        BigInteger y = modSqrtTonelliShanks(rhs, p);
        if (y == null) {
            throw new IllegalArgumentException("No square root for rhs — invalid X for curve");
        }
        BigInteger y1 = y.mod(p);
        BigInteger y2 = p.subtract(y1).mod(p);

        // construct both EC points
        ECPublicKey pub1 = buildEcPublicFromXY(x, y1);
        ECPublicKey pub2 = buildEcPublicFromXY(x, y2);

        candidates.add(pub1);
        // if y1 == y2 (shouldn't happen for p odd), avoid dup
        if (!y1.equals(y2)) candidates.add(pub2);

        return candidates;
    }

    private static ECPublicKey buildEcPublicFromXY(BigInteger x, BigInteger y) throws Exception {
        // Build ECParameterSpec for secp256r1
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPoint w = new ECPoint(x, y);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(pubSpec);
    }

    /**
     * Tonelli-Shanks modular sqrt for prime p (find r s.t. r^2 = n mod p).
     * Returns one root r or null if no root exists.
     * This implementation expects p odd prime. Works for P-256.
     */
    private static BigInteger modSqrtTonelliShanks(BigInteger n, BigInteger p) throws Exception {
        n = n.mod(p);
        if (n.equals(BigInteger.ZERO)) return BigInteger.ZERO;
        // Legendre symbol n^{(p-1)/2} mod p
        BigInteger ls = n.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p);
        if (!ls.equals(BigInteger.ONE)) return null; // no sqrt

        // If p % 4 == 3, sqrt = n^{(p+1)/4} mod p (fast path)
        if (p.testBit(1) && !p.testBit(0)) { // p % 4 == 3
            BigInteger r = n.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
            return r;
        }

        // Tonelli-Shanks general algorithm
        // Factor p-1 = q * 2^s with q odd
        BigInteger q = p.subtract(BigInteger.ONE);
        int s = 0;
        while (q.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            q = q.shiftRight(1);
            s++;
        }

        // find z which is quadratic non-residue
        BigInteger z = BigInteger.TWO;
        while (z.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE)) {
            z = z.add(BigInteger.ONE);
        }

        BigInteger m = BigInteger.valueOf(s);
        BigInteger c = z.modPow(q, p);
        BigInteger t = n.modPow(q, p);
        BigInteger r = n.modPow(q.add(BigInteger.ONE).shiftRight(1), p);

        while (true) {
            if (t.equals(BigInteger.ONE)) return r;
            // find least i (0 < i < m) with t^{2^i} = 1
            int i = 1;
            BigInteger t2i = t.modPow(BigInteger.TWO, p);
            while (!t2i.equals(BigInteger.ONE)) {
                t2i = t2i.modPow(BigInteger.TWO, p);
                i += 1;
                if (i == m.intValue()) return null;
            }
            BigInteger b = c.modPow(BigInteger.valueOf(1L << (m.intValue() - i - 1)), p);
            r = r.multiply(b).mod(p);
            c = b.modPow(BigInteger.TWO, p);
            t = t.multiply(c).mod(p);
            m = BigInteger.valueOf(i);
        }
    }
    public static List<ECPublicKey> parseEcPublicKeyCandidatesFromBase64(String b64) throws Exception {
        byte[] raw = Base64.getDecoder().decode(b64);

        // 1) If Apple sent only X (32 bytes) -> expand to two candidate points
        if (raw.length == 32) {
            logger.info("Detected 32-byte X-only device key. Expanding to two candidates.");
            return expandXToCandidates(raw); // returns list size 2 (usually)
        }

        // 2) If full uncompressed X9.63 (0x04 || X || Y)
        if (raw.length == 65 && raw[0] == 0x04) {
            byte[] xb = Arrays.copyOfRange(raw, 1, 33);
            byte[] yb = Arrays.copyOfRange(raw, 33, 65);
            ECPublicKey pub = buildEcPublicKeyFromXY(xb, yb);
            return List.of(pub);
        }

        // 3) Try to parse as X.509/SPKI DER (typical)
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec ks = new X509EncodedKeySpec(raw);
            PublicKey pk = kf.generatePublic(ks);
            if (pk instanceof ECPublicKey) {
                return List.of((ECPublicKey) pk);
            } else {
                throw new IllegalArgumentException("Parsed public key is not EC");
            }
        } catch (Exception e) {
            logger.warn("Failed to parse as X.509/SPKI: " + e.getMessage() + " — trying to find X9.63 inside the blob...");
            // fallback: search for an embedded 0x04||X||Y
            for (int i = 0; i <= raw.length - 65; i++) {
                if (raw[i] == 0x04) {
                    byte[] x963 = Arrays.copyOfRange(raw, i, i + 65);
                    byte[] xb = Arrays.copyOfRange(x963, 1, 33);
                    byte[] yb = Arrays.copyOfRange(x963, 33, 65);
                    ECPublicKey pub = buildEcPublicKeyFromXY(xb, yb);
                    return List.of(pub);
                }
            }
        }

        throw new IllegalArgumentException("Unrecognized EC public key format");
    }

}
