/* Copyright 2025 University of Oslo, Norway
 # This file is part of Cerebrum.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/

package no.uio.keycloak.psso.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.ConcatKDF;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.jboss.logging.Logger;
import org.json.JSONException;
import org.json.JSONObject;


import org.jose4j.base64url.Base64Url;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;


import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

public class JweBuilder {

    private static final Logger logger = Logger.getLogger(JweBuilder.class);
    /**
     * recipientEcJwk: the recipient's public EC key as Nimbus ECKey (curve must match client).
     * apu/apv: byte[] (apu required). If apv==null then omit.
     * idTokenSigned: compact signed id_token (String)
     * refreshToken: opaque refresh token (String)
     * expiresIn: seconds until expiry
     */
    public static String buildPlatformSsoJwe(
            ECKey recipientEcJwk,   // recipient's EC public key (P-256) as Nimbus ECKey
            byte[] apv,             // client PartyVInfo (may be null)
            String idTokenSigned,
            String refreshToken,
            String expiresIn,
            String refreshExpiresIn,
            String typHeaderValue
    ) throws JOSEException {

        // ensure curve
        if (!"P-256".equals(recipientEcJwk.getCurve().getName())) {
            throw new JOSEException("Recipient EC key must be P-256 for Platform SSO.");
        }

        // Build payload JSON
        JSONObject body = new JSONObject();
        try {
            body.put("id_token", idTokenSigned);
            body.put("refresh_token", refreshToken);
            if (expiresIn != null) body.put("expires_in", expiresIn);
            if (refreshExpiresIn != null) body.put("refresh_token_expires_in", refreshExpiresIn);
            body.put("token_type", "Bearer");
        } catch (JSONException e) {
            throw new JOSEException(e.getMessage());
        }
        Payload payload = new Payload(jsonObjectToMap(body));

        // Build header: ECDH-ES (direct) + A256GCM
        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(
                JWEAlgorithm.ECDH_ES,
                EncryptionMethod.A256GCM
        );

        headerBuilder.type(new JOSEObjectType(typHeaderValue != null ? typHeaderValue : "JWT"));

        if (recipientEcJwk.getKeyID() != null) {
            headerBuilder.keyID(recipientEcJwk.getKeyID());
        }



        // apv optional
        if (apv != null && apv.length > 0) {
            headerBuilder.agreementPartyVInfo(Base64URL.encode(apv));
        }

        String keyId = UUID.randomUUID().toString();
        ECKey epk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key (optional)
                .keyID(keyId) // give the key a unique ID (optional)
                .issueTime(new Date()) // issued-at timestamp (optional)
                .generate();

        // Build X9.63 uncompressed EPK bytes: 0x04 || X || Y
        byte[] x = epk.getX().decode(); // 32 bytes for P-256
        byte[] y = epk.getY().decode(); // 32 bytes
        byte[] x963 = new byte[1 + x.length + y.length];
        x963[0] = 0x04;
        System.arraycopy(x, 0, x963, 1, x.length);
        System.arraycopy(y, 0, x963, 1 + x.length, y.length);

// Build Apple PartyUInfo: 4-byte BE len("APPLE") || "APPLE" || 4-byte BE len(epkX963) || epkX963
        byte[] apple = "APPLE".getBytes(StandardCharsets.UTF_8);
        ByteBuffer apuBb = ByteBuffer.allocate(4 + apple.length + 4 + x963.length);
        apuBb.putInt(apple.length);
        apuBb.put(apple);
        apuBb.putInt(x963.length);
        apuBb.put(x963);
        byte[] apuBytes = apuBb.array();

        headerBuilder.keyID(keyId);
        headerBuilder.ephemeralPublicKey(epk.toPublicJWK());
        headerBuilder.agreementPartyUInfo(Base64URL.encode(apuBytes));
        JWEHeader header = headerBuilder.build();
        JWEObject jweObject = new JWEObject(header, payload);
        Map<String,Object> headerMap = header.toJSONObject();
// derive CEK with your code (you already have deriveCek / generateCEK)
        SecretKey cek = generateCEK(epk, recipientEcJwk.toECPublicKey(), apuBytes, apv);
// ensure cek is AES 32 bytes
        String compact="";
        try {
            compact = buildCompactJweWithCek(headerMap, cek, payload.toString());
        } catch (Exception e) {
            logger.error("Error building compact JWE", e);
        }
        return compact;
    }

    // helper methods


    public static Map<String, Object> jsonObjectToMap(JSONObject json) {
        Map<String, Object> map = new HashMap<>();

        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = json.opt(key);

            if (value instanceof JSONObject) {
                value = jsonObjectToMap((JSONObject) value);
            }

            if (value instanceof org.json.JSONArray) {
                org.json.JSONArray arr = (org.json.JSONArray) value;
                List<Object> list = new ArrayList<>();
                for (int i = 0; i < arr.length(); i++) {
                    Object item;
                    try {
                        item = arr.get(i);
                    } catch (JSONException e) {
                        throw new RuntimeException(e);
                    }
                    if (item instanceof JSONObject) {
                        item = jsonObjectToMap((JSONObject) item);
                    }
                    list.add(item);
                }
                value = list;
            }

            map.put(key, value);
        }

        return map;
    }

    public static SecretKey generateCEK(ECKey epk, ECPublicKey recipientPub, byte[] partyUInfo, byte[] partyVInfo){
        try {
            // 1) raw ECDH
            ECPrivateKey senderPriv = epk.toECPrivateKey();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(senderPriv);
            ka.doPhase(recipientPub, true);
            byte[] zBytes = ka.generateSecret();    // raw shared secret Z

            // Input to the KDF
            SecretKey zKey = new SecretKeySpec(zBytes, "ECDH");

            // 2) build the ConcatKDF otherInfo exactly as RFC7518 requires
            ConcatKDF kdf = new ConcatKDF("SHA-256");

            byte[] algId = ConcatKDF.encodeStringData(EncryptionMethod.A256GCM.getName()); // "A256GCM"

            byte[] partyU = (partyUInfo != null && partyUInfo.length > 0)
                    ? ConcatKDF.encodeDataWithLength(Base64URL.encode(partyUInfo))
                    : ConcatKDF.encodeDataWithLength((Base64URL) null);

            byte[] partyV = (partyVInfo != null && partyVInfo.length > 0)
                    ? ConcatKDF.encodeDataWithLength(Base64URL.encode(partyVInfo))
                    : ConcatKDF.encodeDataWithLength((Base64URL) null);

            byte[] suppPubInfo = ConcatKDF.encodeIntData(256); // bits for A256GCM
            byte[] suppPrivInfo = ConcatKDF.encodeNoData();

            ByteArrayOutputStream other = new ByteArrayOutputStream();
            other.write(algId);
            other.write(partyU);
            other.write(partyV);
            other.write(suppPubInfo);
            other.write(suppPrivInfo);
            byte[] otherInfo = other.toByteArray();

            // 3) derive CEK (256 bits)
            SecretKey rawCek = kdf.deriveKey(zKey, 256, otherInfo);

            // 4) wrap into AES to ensure Nimbus accepts it
            byte[] cekBytes = rawCek.getEncoded();
            if (cekBytes == null || cekBytes.length != 32) {
                throw new IllegalStateException("Derived CEK wrong length: " + (cekBytes==null? "null": cekBytes.length));
            }
            SecretKey cek = new SecretKeySpec(cekBytes, "AES");

            // debug
            return cek;
        } catch (Exception e) {
            logger.error("CEK derivation failed: " + e.toString(), e);
            throw new RuntimeException(e);
        }
    }




    public static String buildCompactJweWithCek(Map<String, Object> headerJson, SecretKey aesCek, String payloadJson) throws Exception {
        // 1) header -> compact Base64URL
        String headerJsonString = com.nimbusds.jose.util.JSONObjectUtils.toJSONString(headerJson);
        Base64URL headerB64 = Base64URL.encode(headerJsonString);

        // 2) encrypted_key is empty for ECDH-ES (direct)
        String encryptedKeyB64 = ""; // empty

        // 3) generate 96-bit IV (12 bytes) - recommended for GCM
        byte[] iv = new byte[12];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(iv);
        Base64URL ivB64 = Base64URL.encode(iv);

        // 4) AAD is ASCII bytes of headerB64 (RFC7516 uses the base64url-encoded header as AAD)
        byte[] aad = headerB64.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        // 5) AES-GCM encrypt payloadJson using aesCek (must be 32 bytes for A256GCM)
        byte[] cekBytes = aesCek.getEncoded();
        if (cekBytes == null || cekBytes.length != 32) {
            throw new IllegalArgumentException("CEK must be 32 bytes for A256GCM");
        }
        SecretKeySpec cekSpec = new SecretKeySpec(cekBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // 128-bit tag length
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, cekSpec, gcmSpec);
        cipher.updateAAD(aad);

        byte[] plaintext = payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] cipherOutput = cipher.doFinal(plaintext);
        // cipherOutput = ciphertext || tag (tag at end)
        int tagLenBytes = 16; // 128 bits
        int ctLen = cipherOutput.length - tagLenBytes;
        byte[] ciphertext = Arrays.copyOfRange(cipherOutput, 0, ctLen);
        byte[] tag = Arrays.copyOfRange(cipherOutput, ctLen, cipherOutput.length);

        Base64URL ciphertextB64 = Base64URL.encode(ciphertext);
        Base64URL tagB64 = Base64URL.encode(tag);

        // 6) Compact serialization: BASE64URL(header) . BASE64URL(encrypted_key) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)
        // encrypted_key is empty string (still keep delimiter)
        String compact = headerB64.toString() + "." + encryptedKeyB64 + "." + ivB64.toString() + "." + ciphertextB64.toString() + "." + tagB64.toString();

        return compact;
    }

    // small helper
    private static String bytesHex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

}
