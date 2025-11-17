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

package no.uio.keycloak.psso;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

public class AppleAttestationVerifier {

    private static final Logger logger = Logger.getLogger(AppleAttestationVerifier.class);
    private final X509Certificate appleRootCert; // Apple Enterprise Attestation Root CA
    private static final String NONCE_OID = "1.2.840.113635.100.8.11.1";
    private static final String SERIAL_OID = "1.2.840.113635.100.8.9.1";
    private static final String DEVICE_UDID_OID = "1.2.840.113635.100.8.9.2";

    DeviceAttestationObject deviceAttestationObject = null;
    public AppleAttestationVerifier(X509Certificate appleRootCert) {
        this.appleRootCert = appleRootCert;
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Verifies Apple device attestation.
     *
     * @param attestationCertsB64   List of Base64 certificates (leaf first)
     * @param deviceSigningKeyB64   Base64 encoded raw device public key
     * @param nonce                 The challenge nonce
     * @return true if attestation is valid
     */
    public boolean verifyAppleAttestation(List<String> attestationCertsB64,
                                          String deviceSigningKeyB64,
                                          String nonce, KeycloakSession session, String clientRequestId) {

        DeviceAttestationObject deviceAttestationObject = new DeviceAttestationObject();
        try {
            // Step 1: Decode certificate chain
            List<X509Certificate> certChain = decodeCertChain(attestationCertsB64);
            if (certChain.isEmpty()) {
                logger.warn("No certificates found in attestation chain");
                return false;
            }

            NonceService nonceService = new NonceService(session);

            if (!nonceService.validateNonce(nonce, clientRequestId)){
                logger.error("Nonce validation failed");
                return false;

            }

            X509Certificate leafCert = certChain.get(0);

            // Step 1.5: Validate certificate chain (Apple-signed)
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(certChain);
            Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(appleRootCert, null));
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(certPath, params);
            logger.debug("Certificate chain validated successfully");

            // Step 2: Log extensions (optional but helpful)
            logCertificateChainExtensions(certChain.toArray(new X509Certificate[0]));

            // Step 3: Public key match
            byte[] leafKeyBytes = extractRawECPoint(leafCert.getPublicKey());
            byte[] clientKeyBytes = decodeRawBase64Key(deviceSigningKeyB64);
            if (!Arrays.equals(leafKeyBytes, clientKeyBytes)) {
                logger.warn("Public key mismatch between attested cert and provided key");
                return false;
            }
            logger.debug("Public key matches device key");

            // Step 4: Compute expected nonce hash (raw nonce string → SHA-256)
            byte[] expectedNonceHash = MessageDigest.getInstance("SHA-256")
                    .digest(nonce.getBytes(StandardCharsets.UTF_8));
            logger.debug("Expected nonce hash (SHA-256): " + Hex.toHexString(expectedNonceHash));

            // Step 5: Extract nonce hash from OID 1.2.840.113635.100.8.11.1
            byte[] extValue = leafCert.getExtensionValue(NONCE_OID);
            if (extValue == null || extValue.length != 34 || extValue[0] != 0x04 || extValue[1] != 0x20) {
                logger.warn("Freshness extension (1.2.840.113635.100.8.11.1) missing or malformed. Got: " +
                        (extValue == null ? "null" : Hex.toHexString(extValue)));
                return false;
            }

            // Step 6: Extract serial number
            byte[] serial = leafCert.getExtensionValue(SERIAL_OID);
            if (serial == null  || serial[0] != 0x04 ) {

                logger.warn("Serial missing or malformed. Got: " +
                        (serial == null ? "null" : Hex.toHexString(serial)));
                return false;
            }

            deviceAttestationObject.setSerial(Hex.toHexString(serial));

            // Step 6: Extract serial number
            byte[] deviceUDid = leafCert.getExtensionValue(DEVICE_UDID_OID);
            if (deviceUDid == null || deviceUDid[0] != 0x04) {
                logger.warn("DeviceUDID missing or malformed. Got: " +
                        (deviceUDid == null ? "null" : Hex.toHexString(deviceUDid)));
                return false;
            }

            String serialString = hexBytesToString(Arrays.copyOfRange(serial, 2, serial.length));
            String deviceUDidString = hexBytesToString(Arrays.copyOfRange(deviceUDid, 2, deviceUDid.length));

            logger.debug("DeviceUDID: " + deviceUDidString);
            logger.debug("Serial: " + serialString);

            deviceAttestationObject.setSerial(serialString);
            deviceAttestationObject.setDeviceUDid(deviceUDidString);

            byte[] nonceInCert = Arrays.copyOfRange(extValue, 2, 34);

            logger.debug("Nonce hash from certificate: " + Hex.toHexString(nonceInCert));

            if (Arrays.equals(nonceInCert, expectedNonceHash)) {
                logger.info("ALL CHECKS PASSED – Serial number: " + serialString + ", Device UDID: " + deviceUDidString + " successfully attested");
                this.deviceAttestationObject = deviceAttestationObject;
                return true;
            } else {
                logger.warn("Nonce mismatch! Device might be replaying old attestation.");
                return false;
            }

        } catch (Exception e) {
            logger.error("Attestation verification failed", e);
            return false;
        }
    }

    // ---------- Helper methods ----------

    private List<X509Certificate> decodeCertChain(List<String> base64Certs) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        for (String b64 : base64Certs) {
            byte[] certBytes = Base64.getDecoder().decode(b64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            certs.add(cert);
        }
        return certs;
    }

    private byte[] extractRawECPoint(PublicKey key) {
        byte[] encoded = key.getEncoded();
        int len = encoded.length;
        if (len > 65) {
            return Arrays.copyOfRange(encoded, len - 65, len);
        }
        return encoded;
    }

    private byte[] decodeRawBase64Key(String base64) {
        String normalized = base64.replace('-', '+').replace('_', '/');
        int padding = (4 - normalized.length() % 4) % 4;
        normalized += "=".repeat(padding);
        return Base64.getDecoder().decode(normalized);
    }

    private void logCertificateChainExtensions(X509Certificate[] chain) {
        logger.debug("🔍 Inspecting full certificate chain for Apple attestation extensions...");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            logger.debug("Certificate [" + i + "]");
            logger.debug("  Subject: " + cert.getSubjectX500Principal());
            logger.debug("  Issuer : " + cert.getIssuerX500Principal());

            Set<String> criticalOids = cert.getCriticalExtensionOIDs();
            if (criticalOids != null) {
                for (String oid : criticalOids) {
                    logger.debug("    Critical OID: " + oid + " (hex: " + Hex.toHexString(cert.getExtensionValue(oid)) + ")");
                }
            }

            Set<String> nonCriticalOids = cert.getNonCriticalExtensionOIDs();
            if (nonCriticalOids != null) {
                for (String oid : nonCriticalOids) {
                    logger.debug("    Non-critical OID: " + oid + " (hex: " + Hex.toHexString(cert.getExtensionValue(oid)) + ")");
                }
            }
        }
    }

    private Map<String, byte[]> extractAppleExtensions(X509Certificate cert, String oidPrefix) {
        Map<String, byte[]> result = new HashMap<>();
        Set<String> oids = new HashSet<>();
        if (cert.getCriticalExtensionOIDs() != null) oids.addAll(cert.getCriticalExtensionOIDs());
        if (cert.getNonCriticalExtensionOIDs() != null) oids.addAll(cert.getNonCriticalExtensionOIDs());

        for (String oid : oids) {
            if (oid.startsWith("1.2.840.113635.")) {
                try {
                    byte[] wrapped = cert.getExtensionValue(oid);
                    if (wrapped != null) {
                        result.put(oid, wrapped);
                    }
                } catch (Exception e) {
                    logger.warn("Failed to parse Apple extension " + oid + ": " + e.getMessage());
                }
            }
        }
        return result;
    }

    public static String hexBytesToString(byte[] bytes) {
        return new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);
    }

}
